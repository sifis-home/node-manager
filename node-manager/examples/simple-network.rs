use node_manager::keys::priv_key_pem_to_der;
use node_manager::{self, timestamp, Message, NodeId, NodeManager, NodeManagerBuilder, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Command line options
struct Opt {
    server: bool,
    start_member: bool,
    addr: Option<String>,
    key_file: Option<String>,
}

impl Opt {
    fn get_addr(&self) -> &str {
        const DEFAULT_ADDR: &str = "127.0.0.1:7000";
        self.addr.as_deref().unwrap_or(DEFAULT_ADDR)
    }
}

fn parse_opt() -> Opt {
    let mut args_iter = std::env::args();
    // First argument is the executable name
    args_iter.next();
    enum Mode {
        Addr,
        KeyFile,
    }
    let mut mode = None;
    let mut opt = Opt {
        server: false,
        start_member: false,
        addr: None,
        key_file: None,
    };
    for arg in args_iter {
        let Some(mode) = mode.take() else {
            match arg.as_str() {
                "--help" => {
                    let exe_name = std::env::args().next().unwrap();
                    println!("Usage: {exe_name} [--server|--client] --private-key <path/to.pem> [--start-member] [--addr <address>] [--help]");
                    std::process::exit(0);
                },
                "--server" => opt.server = true,
                "--client" => opt.server = false,
                "--start-member" => opt.start_member = true,
                "--addr" => mode = Some(Mode::Addr),
                "--private-key" => mode = Some(Mode::KeyFile),
                _ => panic!("Unrecognized option '{arg}'"),
            }
            continue;
        };
        match mode {
            Mode::Addr => opt.addr = Some(arg),
            Mode::KeyFile => opt.key_file = Some(arg),
        }
    }
    opt
}

fn main() {
    let opt = parse_opt();
    env_logger::builder().try_init().unwrap();
    log::info!("Starting {}", if opt.server { "server" } else { "client" });
    let key_file_path = opt
        .key_file
        .as_ref()
        .expect("please specify key file path with --private-key");
    let key_pem =
        std::fs::read_to_string(key_file_path).expect("couldn't read private key file path");
    if opt.server {
        run_server(opt, &key_pem);
    } else {
        run_client(opt, &key_pem);
    }
}

#[derive(Serialize, Deserialize)]
struct Packet {
    network: Option<Vec<u8>>,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum PckForServer {
    /// Request for signature
    SignatureRequest(Vec<u8>),
    /// Request for broadcasting
    BroadcastRequest(Packet),
}

#[derive(Serialize, Deserialize)]
enum PckForClient {
    /// Addition message for admin
    SignedAddByAdmin(Vec<u8>, Vec<u8>),
    /// A broadcast packet
    Packet(Packet),
}

struct PckRdr {
    first_unfilled: usize,
    vec: Vec<u8>,
}

impl PckRdr {
    fn new() -> Self {
        Self {
            first_unfilled: 0,
            vec: vec![0; 8],
        }
    }
    fn reset(&mut self) {
        self.first_unfilled = 0;
    }
    fn read_until_timeout(&mut self, stream: &mut TcpStream) -> bool {
        loop {
            match stream.read(&mut self.vec[self.first_unfilled..]) {
                Ok(read) => {
                    if read == 0 {
                        return false;
                    }
                    //log::debug!("read {read} many bytes: {:?}", &&self.vec[self.first_unfilled..][..read]);
                    self.first_unfilled += read;
                    if self.first_unfilled == self.vec.len() {
                        return true;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return false;
                }
                Err(e) => panic!("Couldn't read from TCP stream: {e:?}"),
            }
        }
    }
    fn maybe_read_pck<T: for<'a> Deserialize<'a>>(&mut self, stream: &mut TcpStream) -> Option<T> {
        if self.read_until_timeout(stream) {
            let len = u64::from_be_bytes(self.vec[..8].try_into().unwrap());
            self.reset();
            let mut buf = vec![0; len as usize];
            stream.read_exact(&mut buf).unwrap();
            let pck: T = bincode::deserialize(&buf).unwrap();
            //log::debug!("received packet with data length {}", pck.data.len());
            Some(pck)
        } else {
            None
        }
    }
}

const READ_TIMEOUT: Duration = Duration::from_millis(50);

const LOOP_SLEEP_AMOUNT: Duration = Duration::from_millis(50);

fn handle_client(
    recv: Receiver<Arc<[u8]>>,
    sender: Sender<(u32, PckForServer)>,
    id: u32,
    mut stream: TcpStream,
) {
    stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    thread::spawn(move || {
        let mut pck_rdr = PckRdr::new();
        loop {
            match recv.try_recv() {
                Ok(buf) => {
                    match stream.write_all(&buf) {
                        Ok(_) => (),
                        // Disconnected, end the loop
                        Err(e) if e.kind() == ErrorKind::BrokenPipe => break,
                        Err(e) => panic!("I/O error: {e:?}"),
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    // The server is terminating. Close the connection.
                    break;
                }
                Err(TryRecvError::Empty) => {
                    // Nothing is to be sent. This is normal,
                    // go back to reading on the network.
                }
            }
            if let Some(pck) = pck_rdr.maybe_read_pck(&mut stream) {
                if sender.send((id, pck)).is_err() {
                    // The channel was closed. The server is terminating.
                    break;
                }
            }
            // Sleep a little
            std::thread::sleep(LOOP_SLEEP_AMOUNT);
        }
    });
}

fn run_server(opt: Opt, key_pem: &str) {
    let listen_addr = opt.get_addr();
    println!("Listening at {listen_addr}");
    let listener = TcpListener::bind(listen_addr).unwrap();
    listener.set_nonblocking(true).unwrap();

    #[allow(clippy::type_complexity)]
    let mut client_list: Vec<Option<(Sender<Arc<[u8]>>,)>> = Vec::new();
    let (pcks_for_srv_snd, pcks_for_srv_rcv) = channel();

    let admin_key_pair_der = priv_key_pem_to_der(key_pem);
    let admin = node_manager::admin::AdminNode::from_key_pair_der(&admin_key_pair_der);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                log::debug!("New connection from {}", stream.peer_addr().unwrap());
                let (msgs_in_net_snd, msgs_in_net_rcv) = channel();
                handle_client(
                    msgs_in_net_rcv,
                    pcks_for_srv_snd.clone(),
                    client_list.len() as u32,
                    stream,
                );
                client_list.push(Some((msgs_in_net_snd,)));
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => (),
            Err(e) => panic!("IO error: {e}"),
        }

        match pcks_for_srv_rcv.try_recv() {
            Ok((from_id, pck)) => {
                match pck {
                    PckForServer::SignatureRequest(public_key_der) => {
                        // Send the packet to all the client threads
                        log::debug!("Signing AdminAdd for client id {from_id}");

                        let ts = timestamp().unwrap();
                        let msg_add = admin.sign_addition(&public_key_der, ts).unwrap();
                        let msg_add_buf = bincode::serialize(&msg_add).unwrap();
                        let pck =
                            PckForClient::SignedAddByAdmin(msg_add_buf, admin.public_key_der());

                        let buf = bincode::serialize(&pck).unwrap();
                        let mut buf_with_len = (buf.len() as u64).to_be_bytes().to_vec();
                        buf_with_len.extend_from_slice(&buf);

                        let msg_to_send: Arc<[u8]> = buf_with_len.into();

                        let client = &mut client_list[from_id as usize];
                        let sending_res = if let Some((msgs_in_net_snd,)) = client {
                            msgs_in_net_snd.send(msg_to_send.clone())
                        } else {
                            Ok(())
                        };
                        if sending_res.is_err() {
                            // The client has disconnected.
                            // Remove it from the list.
                            *client = None;
                        }
                    }
                    PckForServer::BroadcastRequest(pck) => {
                        // Send the packet to all the client threads
                        log::debug!(
                            "Sending packet with data len {} to {} clients (lobby={})",
                            pck.data.len(),
                            client_list.iter().filter(|cl| cl.is_some()).count(),
                            pck.network.is_none()
                        );
                        let buf = bincode::serialize(&PckForClient::Packet(pck)).unwrap();
                        let mut buf_with_len = (buf.len() as u64).to_be_bytes().to_vec();
                        buf_with_len.extend_from_slice(&buf);
                        let msg_to_send: Arc<[u8]> = buf_with_len.into();
                        for client in client_list.iter_mut() {
                            let sending_res = if let Some((msgs_in_net_snd,)) = client {
                                msgs_in_net_snd.send(msg_to_send.clone())
                            } else {
                                Ok(())
                            };
                            if sending_res.is_err() {
                                // The client has disconnected.
                                // Remove it from the list.
                                *client = None;
                            }
                        }
                    }
                }
            }
            Err(TryRecvError::Disconnected) => {
                // The client is terminating. Close the connection.
                break;
            }
            Err(TryRecvError::Empty) => {
                // Nothing is to be sent. This is normal,
                // go back to reading on the network.
            }
        }
        // Sleep a little
        std::thread::sleep(LOOP_SLEEP_AMOUNT);
    }
}

// TODO deduplicate this with the usage in tests/
fn make_node_manager_key(pem: &str, key: Option<Vec<u8>>) -> NodeManager {
    fn id_gen_fn(data: &[u8]) -> Result<Vec<u8>, ()> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let bytes = hasher.finalize()[..8].to_vec();
        Ok(bytes)
    }

    let mut builder = NodeManagerBuilder::new(&priv_key_pem_to_der(pem), id_gen_fn);
    if let Some(key) = key {
        builder = builder.shared_key(key);
    }
    builder.build()
}

fn make_stdin_thread() -> Receiver<String> {
    let (sender, receiver) = channel();
    thread::spawn(move || {
        for l in std::io::stdin().lines() {
            let l = l.unwrap();
            if sender.send(l).is_err() {
                // Disconnected
                break;
            }
        }
    });
    receiver
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let mut res = Vec::new();
    for v in 0..(s.len() / 2) {
        let byte_str = s.get((v * 2)..)?.get(..2)?;
        let byte = u8::from_str_radix(&byte_str, 16).ok()?;
        res.push(byte);
    }
    Some(res)
}

fn run_client(opt: Opt, key_pem: &str) {
    let listen_addr = opt.get_addr();
    let mut stream = TcpStream::connect(listen_addr).unwrap();

    stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

    let shared_key_opt = opt
        .start_member
        .then(|| node_manager::gen_shared_key().to_vec());

    let mut node = make_node_manager_key(key_pem, shared_key_opt);

    let mut pck_rdr = PckRdr::new();
    let stdin_input = make_stdin_thread();

    // Cache the shared key as it might change during the message
    // handling. If we then process the responses, we should use the
    // original key (or the one set by a SetSharedKey response).
    let mut node_shared_key = node.shared_key().to_vec();
    let mut resps = Vec::new();
    loop {
        if let Some(pck) = pck_rdr.maybe_read_pck::<PckForClient>(&mut stream) {
            match pck {
                PckForClient::SignedAddByAdmin(msg_add_buf, admin_public_key_der) => {
                    node.add_admin_key_der(&admin_public_key_der).unwrap();
                    let msg_add: Message = bincode::deserialize(&msg_add_buf).unwrap();
                    resps.extend_from_slice(&[Response::Message(msg_add, false)]);
                }
                PckForClient::Packet(pck) => {
                    if let Some(network) = &pck.network {
                        if network != &node_shared_key {
                            continue;
                        }
                    }
                    let in_members_network = pck.network.is_some();
                    resps.extend_from_slice(
                        &node.handle_msg(&pck.data, in_members_network).unwrap(),
                    );
                }
            }
        }
        let ts = timestamp().unwrap();
        match stdin_input.try_recv() {
            Ok(line) => {
                match line.to_ascii_lowercase().as_str() {
                    "join" | "j" => {
                        // Join
                        let buf = bincode::serialize(&PckForServer::SignatureRequest(
                            node.public_key_der(),
                        ))
                        .unwrap();
                        stream.write_all(&(buf.len() as u64).to_be_bytes()).unwrap();
                        stream.write_all(&buf).unwrap();
                    }
                    "pause" | "p" => {
                        // Self Pause
                        let msg_self_pause = node.self_pause(ts).unwrap();
                        resps.extend_from_slice(&msg_self_pause);
                    }
                    "rejoin" | "r" => {
                        // Rejoin
                        let msg_self_rejoin = node.self_rejoin(ts).unwrap();
                        resps.extend_from_slice(&msg_self_rejoin);
                    }
                    "info" | "i" | "t" => {
                        // Info
                        println!("Own ID: {:?}", NodeId::from_data(node.node_id()));
                        // TODO find a better way to print the hex array
                        println!("Shared key: {:?}", NodeId::from_data(node.shared_key()));
                        println!("Node table: {}", node.table_str());
                    }
                    line if line.starts_with("start-vote ") => {
                        let id_str = line.split(' ').nth(1).unwrap();
                        let partial_id = parse_hex(id_str);
                        if let Some(partial_id) = partial_id {
                            let id_opt = node.complete_node_id(&partial_id);
                            if let Some(id) = id_opt {
                                let msgs_vote = node.start_vote(ts, &id).unwrap();
                                resps.extend_from_slice(&msgs_vote);
                            } else {
                                println!(
                                    "error: couldn't find node id '{id_str}' or it was not unique"
                                );
                            }
                        } else {
                            println!("invalid hex array: '{id_str}'");
                        }
                    }
                    _ => {
                        println!("error: Unrecognized command '{line}'");
                        println!("Commands: join pause rejoin info start-vote");
                    }
                }
            }
            Err(TryRecvError::Disconnected) => {
                // The client is terminating. Close the connection.
                break;
            }
            Err(TryRecvError::Empty) => {
                // Nothing is to be sent. This is normal,
                // go back to reading on the network.
            }
        }
        for resp in std::mem::take(&mut resps) {
            match resp {
                Response::SetSharedKey(k) => {
                    log::info!("Setting shared key...");
                    node_shared_key = k.to_vec();
                }
                Response::Message(msg, on_members_network) => {
                    let network = on_members_network.then(|| node_shared_key.clone());
                    let data = bincode::serialize(&msg).unwrap();
                    let pck = Packet { network, data };
                    let buf = bincode::serialize(&PckForServer::BroadcastRequest(pck)).unwrap();
                    stream.write_all(&(buf.len() as u64).to_be_bytes()).unwrap();
                    stream.write_all(&buf).unwrap();
                }
            }
        }
        // Sleep a little
        std::thread::sleep(LOOP_SLEEP_AMOUNT);
    }
}
