use node_manager::{self, NodeId, NodeManager, NodeManagerBuilder, Response};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
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
        self.addr
            .as_ref()
            .map(String::as_str)
            .unwrap_or(DEFAULT_ADDR)
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
    while let Some(arg) = args_iter.next() {
        let Some(mode) = mode.take() else {
            match arg.as_str() {
                "--help" => {
                    let exe_name = std::env::args().nth(0).unwrap();
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
    sender: Sender<(u32, Packet)>,
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
                if let Err(_) = sender.send((id, pck)) {
                    // The channel was closed. The server is terminating.
                    break;
                }
            }
            // Sleep a little
            std::thread::sleep(LOOP_SLEEP_AMOUNT);
        }
    });
}

fn run_server(opt: Opt, _key_pem: &str) {
    let listen_addr = opt.get_addr();
    println!("Listening at {listen_addr}");
    let listener = TcpListener::bind(listen_addr).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client_list: Vec<Option<(Sender<Arc<[u8]>>,)>> = Vec::new();
    let (pcks_to_brd_snd, pcks_to_brd_rcv) = channel();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                log::debug!("New connection from {}", stream.peer_addr().unwrap());
                let (msgs_in_net_snd, msgs_in_net_rcv) = channel();
                handle_client(
                    msgs_in_net_rcv,
                    pcks_to_brd_snd.clone(),
                    client_list.len() as u32,
                    stream,
                );
                client_list.push(Some((msgs_in_net_snd,)));
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => (),
            Err(e) => panic!("IO error: {e}"),
        }

        match pcks_to_brd_rcv.try_recv() {
            Ok((_from_id, pck)) => {
                // Send the packet to all the client threads
                log::debug!(
                    "Sending packet with data len {} to {} clients (lobby={})",
                    pck.data.len(),
                    client_list.iter().filter(|cl| cl.is_some()).count(),
                    pck.network.is_none()
                );
                let buf = bincode::serialize(&pck).unwrap();
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
fn key_pem_to_der(key_pem: &str) -> Vec<u8> {
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem).unwrap();
    let key_der = key.to_pkcs8_der().unwrap();

    let key_der_slice: &[u8] = key_der.as_ref();
    key_der_slice.to_vec()
}

// TODO deduplicate this with the usage in tests/
fn make_node_manager_key(pem: &str, key: Option<Vec<u8>>) -> NodeManager {
    fn id_gen_fn(data: &[u8]) -> Result<Vec<u8>, ()> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let bytes = hasher.finalize()[..8].to_vec();
        Ok(bytes)
    }

    let mut builder = NodeManagerBuilder::new(&key_pem_to_der(pem), id_gen_fn);
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

// TODO deduplicate with function in node-manager
fn timestamp() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let mut res = Vec::new();
    for byte_hex in s.as_bytes().chunks(2) {
        let hex_digit = |byte| {
            Some(match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => return None,
            })
        };
        if let (Some(hi), Some(lo)) = (hex_digit(byte_hex[0]), hex_digit(byte_hex[1])) {
            res.push((hi << 4) | lo);
        } else {
            return None;
        }
    }
    Some(res)
}

fn run_client(opt: Opt, key_pem: &str) {
    let listen_addr = opt.get_addr();
    let mut stream = TcpStream::connect(listen_addr).unwrap();

    stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

    // TODO: run the admin node on the server and ask it for signatures
    let admin_key_pem = std::fs::read_to_string("tests/keys/test_key1.pem").unwrap();
    let admin_key_pair_der = key_pem_to_der(&admin_key_pem);
    let admin = node_manager::admin::AdminNode::from_key_pair_der(&admin_key_pair_der);

    let shared_key_opt = opt
        .start_member
        .then(|| node_manager::gen_shared_key().to_vec());

    let mut node = make_node_manager_key(key_pem, shared_key_opt);
    node.add_admin_key_der(&admin.public_key_der()).unwrap();

    let mut pck_rdr = PckRdr::new();
    let stdin_input = make_stdin_thread();

    // Cache the shared key as it might change during the message
    // handling. If we then process the responses, we should use the
    // original key (or the one set by a SetSharedKey response).
    let mut node_shared_key = node.shared_key().to_vec();
    let mut resps = Vec::new();
    loop {
        if let Some(pck) = pck_rdr.maybe_read_pck::<Packet>(&mut stream) {
            if let Some(network) = &pck.network {
                if network != &node_shared_key {
                    continue;
                }
            }
            let in_members_network = pck.network.is_some();
            resps.extend_from_slice(&node.handle_msg(&pck.data, in_members_network).unwrap());
        }
        let ts = timestamp();
        match stdin_input.try_recv() {
            Ok(line) => {
                match line.to_ascii_lowercase().as_str() {
                    "join" | "j" => {
                        // Join
                        let msg_add = admin.sign_addition(&node.public_key_der(), ts).unwrap();
                        resps.extend_from_slice(&[Response::Message(msg_add, false)]);
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
                        println!("Own ID: {:?}", NodeId::from_data(&node.node_id()));
                        // TODO find a better way to print the hex array
                        println!("Shared key: {:?}", NodeId::from_data(&node.shared_key()));
                        println!("Node table: {}", node.table_str());
                    }
                    line if line.starts_with("start-vote ") => {
                        let id_str = line.split(' ').nth(1).unwrap();
                        let partial_id = parse_hex(&id_str);
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
                    let buf = bincode::serialize(&pck).unwrap();
                    stream.write_all(&(buf.len() as u64).to_be_bytes()).unwrap();
                    stream.write_all(&buf).unwrap();
                }
            }
        }
        // Sleep a little
        std::thread::sleep(LOOP_SLEEP_AMOUNT);
    }
}
