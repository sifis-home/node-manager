# node-manager

[![Actions Status][actions badge]][actions]
[![CodeCov][codecov badge]][codecov]
[![LICENSE][license badge]][license]

The SIFIS-Home NodeManager component contains the logic to collectively
decide upon membership statuses for SIFIS-Home enabled smart devices.

It interfaces with the [DHT component](https://github.com/sifis-home/libp2p-rust-dht).

# Running the `simple-network` example

The `simple-network` example is provided as a demonstration of the node-manager
running in a network setting. It provides server and client parts, where the
server is responsible for broadcasting messages among the clients, and the clients
each run a node.

The clients can accept commands from the command line.
The following commands are accepted:

- `join`
- `pause`
- `rejoin`
- `info`
- `start-vote`

For example, you can run these commands in parallel shell sessions:

```
RUST_LOG="node_manager=debug,simple_network=debug" cargo run --example simple-network -- --server --private-key tests/keys/test_key1.pem

RUST_LOG="node_manager=debug,simple_network=debug" cargo run --example simple-network -- --client --start-member --private-key tests/keys/test_key2.pem

RUST_LOG="node_manager=debug,simple_network=debug" cargo run --example simple-network -- --client --private-key tests/keys/test_key3.pem

RUST_LOG="node_manager=debug,simple_network=debug" cargo run --example simple-network -- --client --private-key tests/keys/test_key4.pem
```

Here, one server is started connected to three nodes. One is specified as start member, possessing the shared key.
The other nodes can then request to join via the `join` command.

# The web assembly admin key example

For the the joining workflow, the node manager relies on an admin key signing
the public key of the joining node. This key is created and managed by the
SIFIS-Home network creator's mobile application. In order to demonstrate the
usage from javascript, we provide a simple html based demo of the admin
component compiled to web assembly and viewable in the browser.

## Building and running

* obtain [wasm-pack](https://github.com/rustwasm/wasm-pack)
* cd into `nmgr-admin-wasm-api`
* execute `wasm-pack build --target web` to build the web assembly file and the glue js files
* run a http server from that directory, for example via `python3 -m http.server`
* in the browser, navigate to `http://localhost:8000/admin-demo.html` to see the demo

# Acknowledgements

This software has been developed in the scope of the H2020 project SIFIS-Home with GA n. 952652.

<!-- Links -->
[actions]: https://github.com/sifis-home/node-manager/actions
[codecov]: https://codecov.io/gh/sifis-home/node-manager
[license]: LICENSE

<!-- Badges -->
[actions badge]: https://github.com/sifis-home/node-manager/workflows/node-manager/badge.svg
[codecov badge]: https://codecov.io/gh/sifis-home/node-manager/branch/master/graph/badge.svg
[license badge]: https://img.shields.io/badge/license-MIT-blue.svg
