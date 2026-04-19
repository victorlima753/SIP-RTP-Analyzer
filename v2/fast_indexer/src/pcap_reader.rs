use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

pub(crate) const LINKTYPE_ETHERNET: u32 = 1;
pub(crate) const LINKTYPE_LINUX_SLL: u32 = 113;
pub(crate) const LINKTYPE_RAW: u32 = 101;

const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

#[derive(Debug, Clone, Copy)]
pub(crate) struct PcapHeaderInfo {
    pub(crate) linktype: u32,
    pub(crate) is_pcapng: bool,
}

pub(crate) struct PcapPacket<'a> {
    pub(crate) ts_epoch: f64,
    pub(crate) data: &'a [u8],
}

pub(crate) struct PcapReader {
    file: BufReader<File>,
    swapped: bool,
    ns_resolution: bool,
    linktype: u32,
    buffer: Vec<u8>,
}

impl PcapReader {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut header = [0_u8; 24];
        file.read_exact(&mut header)?;
        let info = parse_header_info(&header);
        if info.is_pcapng {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PCAPNG ainda nao e suportado pelo caminho rapido Rust",
            ));
        }
        let (swapped, ns_resolution) = magic_flags(&header);
        Ok(Self {
            file: BufReader::with_capacity(1024 * 1024, file),
            swapped,
            ns_resolution,
            linktype: info.linktype,
            buffer: Vec::with_capacity(65536),
        })
    }

    pub(crate) fn header_info(path: &Path) -> io::Result<PcapHeaderInfo> {
        let mut file = File::open(path)?;
        let mut header = [0_u8; 24];
        file.read_exact(&mut header)?;
        Ok(parse_header_info(&header))
    }

    pub(crate) fn linktype(&self) -> u32 {
        self.linktype
    }

    fn read_u32(&self, bytes: [u8; 4]) -> u32 {
        if self.swapped {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    }

    pub(crate) fn next_packet(&mut self, read_payload: bool) -> io::Result<Option<PcapPacket<'_>>> {
        let mut header = [0_u8; 16];
        match self.file.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err),
        }
        let ts_sec = self.read_u32([header[0], header[1], header[2], header[3]]);
        let ts_frac = self.read_u32([header[4], header[5], header[6], header[7]]);
        let incl_len = self.read_u32([header[8], header[9], header[10], header[11]]) as usize;
        self.buffer.clear();
        if read_payload {
            self.buffer.resize(incl_len, 0_u8);
            self.file.read_exact(&mut self.buffer)?;
        } else {
            self.file.seek_relative(incl_len as i64)?;
        }
        let divisor = if self.ns_resolution {
            1_000_000_000.0
        } else {
            1_000_000.0
        };
        Ok(Some(PcapPacket {
            ts_epoch: ts_sec as f64 + ts_frac as f64 / divisor,
            data: self.buffer.as_slice(),
        }))
    }
}

pub(crate) fn is_supported_linktype(linktype: u32) -> bool {
    matches!(
        linktype,
        LINKTYPE_ETHERNET | LINKTYPE_LINUX_SLL | LINKTYPE_RAW
    )
}

fn parse_header_info(header: &[u8; 24]) -> PcapHeaderInfo {
    if header[..4] == PCAPNG_MAGIC {
        return PcapHeaderInfo {
            linktype: 0,
            is_pcapng: true,
        };
    }
    let (swapped, _) = magic_flags(header);
    PcapHeaderInfo {
        linktype: read_u32_with_order([header[20], header[21], header[22], header[23]], swapped),
        is_pcapng: false,
    }
}

fn magic_flags(header: &[u8; 24]) -> (bool, bool) {
    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    match magic {
        0xa1b2c3d4 => (false, false),
        0xd4c3b2a1 => (true, false),
        0xa1b23c4d => (false, true),
        0x4d3cb2a1 => (true, true),
        _ => (false, false),
    }
}

fn read_u32_with_order(bytes: [u8; 4], swapped: bool) -> u32 {
    if swapped {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pcapng_header() {
        let mut header = [0_u8; 24];
        header[..4].copy_from_slice(&PCAPNG_MAGIC);
        let info = parse_header_info(&header);
        assert!(info.is_pcapng);
    }

    #[test]
    fn reads_classic_pcap_linktype() {
        let mut header = [0_u8; 24];
        header[..4].copy_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        header[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        let info = parse_header_info(&header);
        assert!(!info.is_pcapng);
        assert_eq!(info.linktype, LINKTYPE_ETHERNET);
    }
}
