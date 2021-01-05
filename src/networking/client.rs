use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, Sender};

pub struct Client {
    tcp_client: mut TcpClient
}

impl Client {
    fn send_messages(
        msrpc_receive_channel: Receiver<Vec<u8>>,
        mut tcp_client: TcpClient,
        encryption_key: &[u8; 32]
    )
    {
        
    }
}