use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use flume::{Receiver, Sender};
use tokio::net::{ToSocketAddrs, UdpSocket};

use crate::router::udp::packet::Packet;

pub mod packet;

pub struct UdpRouter {}

struct SocketWrapper {
    socket: UdpSocket,
    command_rx: Receiver<RouterCommand>,
    packet_tx: Sender<(Packet, SocketAddr)>,
}
enum RouterCommand {
    SendPacket(Packet, SocketAddr),
    Stop,
}

impl SocketWrapper {
    async fn send_recv_loop(&mut self) -> Result<(), ()> {
        let mut buf = BytesMut::with_capacity(1024);
        loop {
            tokio::select! {
                val = self.command_rx.recv_async() => {
                    let cmd = val.map_err(|_| ())?;
                    self.process_command(cmd).await?;
                }
                val = self.socket.recv_from(&mut buf) => {
                    match val {
                        Ok(sat) => self.process_packet(sat, buf.clone().freeze()).await?,
                        Err(_) => todo!("Handle recv error"),
                    }
                }
            }
        }
    }

    async fn process_command(&self, cmd: RouterCommand) -> Result<(), ()> {
        match cmd {
            RouterCommand::SendPacket(packet, addr) => {
                self.socket
                    .send_to(&packet.as_bytes(), addr)
                    .await
                    .map_err(|_| todo!("This needs to be processed"))?;
                Ok(())
            }
            RouterCommand::Stop => Err(()),
        }
    }

    async fn process_packet(
        &self,
        (size, addr): (usize, SocketAddr),
        buf: Bytes,
    ) -> Result<(), ()> {
        assert_eq!(buf.len(), size);
        if let Ok(packet) = packet::parse(buf) {
            self.packet_tx
                .send_async((packet, addr))
                .await
                .map_err(|_| ())?;
        }
        todo!("Inform partner of invalid packet, or blacklist to avoid amplification attacks")
    }
}

impl UdpRouter {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> tokio::io::Result<UdpRouter> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;

        let (msg_tx, msg_rx) = flume::bounded::<RouterCommand>(128);
        let (recv_tx, recv_rx) = flume::bounded::<(packet::Packet, SocketAddr)>(128);

        let mut wrapper = SocketWrapper {
            socket,
            command_rx: msg_rx,
            packet_tx: recv_tx,
        };

        tokio::spawn(async move { wrapper.send_recv_loop().await });

        todo!()
    }
}
