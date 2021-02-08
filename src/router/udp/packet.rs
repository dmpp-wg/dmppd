use bytes::{Buf, BytesMut};
use bytes::{BufMut, Bytes};
use std::hash::Hasher;

#[derive(Debug)]
pub struct Packet(PacketHeader, Bytes);

#[derive(Debug)]
pub struct PacketHeader {
    context: u64,
    len: u16,
    /// CRC32 Hash
    hash: u32,
}

#[derive(Debug)]
pub enum PacketParseError {
    InvalidPacketSize,
    InvalidDataSize,
    CRC32Mismatch(Packet),
}

impl Packet {
    pub fn as_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(14 + self.1.len());
        let PacketHeader { context, len, hash } = self.0;
        bytes.put_u64(context);
        bytes.put_u16(len);
        bytes.put_u32(hash);
        bytes.put(self.1.clone());
        bytes.freeze()
    }
}

pub fn parse(mut bytes: Bytes) -> Result<Packet, PacketParseError> {
    if bytes.len() < 14 {
        return Err(PacketParseError::InvalidPacketSize);
    }

    let context = bytes.get_u64();
    let len = bytes.get_u16();
    let hash = bytes.get_u32();
    let header = PacketHeader { context, len, hash };
    let packet = Packet(header, bytes);

    if len as usize != packet.1.len() {
        return Err(PacketParseError::InvalidDataSize);
    }

    // Checking crc32 hash
    let crc32 = {
        let mut hasher = crc32fast::Hasher::new();
        hasher.write(packet.1.as_ref());
        hasher.finalize()
    };

    if hash != crc32 {
        Err(PacketParseError::CRC32Mismatch(packet))
    } else {
        Ok(packet)
    }
}
