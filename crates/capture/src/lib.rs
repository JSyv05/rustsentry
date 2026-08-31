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

/// TODO(week 1): implement live capture via pcap::Device::lookup() + .open()
pub struct LiveCapture {
    capture: pcap::Capture<pcap::Active>,
}

impl LiveCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            capture: pcap::Device::lookup()?
                .context("no default device found")?
                .open()?,
        })
    }
}

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

/// TODO(week 1): implement replay via pcap::Capture::from_file()
/// Recommended: get this working *before* LiveCapture — it sidesteps
/// capture-permission issues while you build out the parser/flow/detect
/// stages, per the capstone plan.
pub struct PcapFileReplay {
    // file handle goes here
    capture: pcap::Capture<pcap::Offline>,
}

impl PcapFileReplay {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(Self {
            capture: pcap::Capture::from_file(path)?,
        })
    }
}

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
