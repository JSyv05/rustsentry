//! Capture layer: wraps live pcap capture and offline .pcap file replay
//! behind a single interface, so the rest of the pipeline doesn't care
//! which one it's reading from.

use anyhow::Context;
use anyhow::Result;

/// A single captured frame: raw bytes plus the timestamp libpcap gave it.
pub struct RawFrame {
    pub timestamp_micros: i64,
    pub data: Vec<u8>,
}

pub trait FrameSource {
    fn next_frame(&mut self) -> Result<Option<RawFrame>>;
}

/// LiveCapture implements active network sniffing. The struct uses
/// an active capture, which is used whenever you are getting packets
/// from a running device.

pub struct LiveCapture {
    capture: pcap::Capture<pcap::Active>,
}

/// Constructer checks to see if a default network device
/// exists, and constructs if one does.

impl LiveCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            capture: pcap::Device::lookup()?
                .context("no default device found")?
                .open()?,
        })
    }
}

/// next_frame checks to see if there is another packet to read. If there is,
/// then it will return the time and the data associated with the frame.
/// if it cant capture any more packets for any reason, then the program ends,
/// otherwise, it sends an error.

impl FrameSource for LiveCapture {
    fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(Some(RawFrame {
                timestamp_micros: packet.header.ts.tv_sec * 1_000_000 + packet.header.ts.tv_usec,
                data: packet.data.to_vec(),
            })),
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// PcapFileReplay implements file reading to this project
/// the struct uses an offline Capture, which means a .pcap file.
/// Constructor takes a path as an argument, and constructs if the
/// path exists.

pub struct PcapFileReplay {
    // file handle goes here
    capture: pcap::Capture<pcap::Offline>,
}

/// Constructor takes a path as an argument, and constructs if the
/// path exists.

impl PcapFileReplay {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(Self {
            capture: pcap::Capture::from_file(path)?,
        })
    }
}

/// next_frame checks to see if there is another packet to read. If there is,
/// then it will return the time and the data associated with the frame.
/// if there are no more frames in the .pcap file, then the program ends,
/// otherwise, it sends an error.

impl FrameSource for PcapFileReplay {
    fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(Some(RawFrame {
                timestamp_micros: packet.header.ts.tv_sec * 1_000_000 + packet.header.ts.tv_usec,
                data: packet.data.to_vec(),
            })),
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
