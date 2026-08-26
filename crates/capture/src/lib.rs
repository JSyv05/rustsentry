//! Capture layer: wraps live pcap capture and offline .pcap file replay
//! behind a single interface, so the rest of the pipeline doesn't care
//! which one it's reading from.

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
    // device handle goes here
}

/// TODO(week 1): implement replay via pcap::Capture::from_file()
/// Recommended: get this working *before* LiveCapture — it sidesteps
/// capture-permission issues while you build out the parser/flow/detect
/// stages, per the capstone plan.
pub struct PcapFileReplay {
    // file handle goes here
}
