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

/// Outcome of polling a `FrameSource` once.
///
/// This is three states, not two, on purpose: collapsing "no frame right
/// now, but the stream is still live" and "the stream is permanently over"
/// into a single `None` would make a live capture's idle read-timeout look
/// identical to a replay file finishing — which would end the whole
/// program the first time live traffic goes quiet for 100ms.
pub enum FrameEvent {
    /// A frame was captured.
    Frame(RawFrame),
    /// No frame arrived within the read timeout, but the source is still
    /// live — call `next_frame` again. Gives the caller a chance to run
    /// time-based work (e.g. flow eviction) even during quiet traffic.
    Timeout,
    /// The source is exhausted (end of a replayed file). Stop calling.
    Eof,
}

pub trait FrameSource {
    fn next_frame(&mut self) -> Result<FrameEvent>;
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
    fn activate(device: pcap::Device) -> Result<Self> {
        Ok(Self {
            capture: pcap::Capture::from_device(device)?
                .promisc(true)
                .timeout(100)
                .immediate_mode(true)
                .open()?,
        })
    }

    pub fn new() -> Result<Self> {
        let device = pcap::Device::lookup()?.context("no default device found")?;
        Self::activate(device)
    }

    pub fn on_device(name: &str) -> Result<Self> {
        let device = pcap::Device::list()?
            .into_iter()
            .find(|d| d.name == name)
            .context("device not found")?;
        Self::activate(device)
    }
}

/// Lists network devices available for live capture (see `LiveCapture::on_device`).
/// Device names are platform- and machine-specific (e.g. `eth2` on one box,
/// `enp10s0` on another), so callers should list rather than guess.
pub fn list_devices() -> Result<Vec<pcap::Device>> {
    Ok(pcap::Device::list()?)
}

/// next_frame checks to see if there is another packet to read. If there is,
/// then it will return the time and the data associated with the frame.
/// if it cant capture any more packets for any reason, then the program ends,
/// otherwise, it sends an error.

impl FrameSource for LiveCapture {
    fn next_frame(&mut self) -> Result<FrameEvent> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(FrameEvent::Frame(RawFrame {
                timestamp_micros: packet.header.ts.tv_sec * 1_000_000 + packet.header.ts.tv_usec,
                data: packet.data.to_vec(),
            })),
            Err(pcap::Error::NoMorePackets) => Ok(FrameEvent::Eof),
            Err(pcap::Error::TimeoutExpired) => Ok(FrameEvent::Timeout),
            Err(e) => {
                eprintln!("frame source error: {:?}", e);
                Err(e.into())
            }
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
    fn next_frame(&mut self) -> Result<FrameEvent> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(FrameEvent::Frame(RawFrame {
                timestamp_micros: packet.header.ts.tv_sec * 1_000_000 + packet.header.ts.tv_usec,
                data: packet.data.to_vec(),
            })),
            Err(pcap::Error::NoMorePackets) => Ok(FrameEvent::Eof),
            Err(e) => Err(e.into()),
        }
    }
}
