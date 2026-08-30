//! Entry point: wires capture -> parser -> flow -> detect together and
//! prints/logs alerts. Week 1 goal: this compiles and runs, even if every
//! stage below it is still a todo!().

use capture::{FrameSource, PcapFileReplay};

fn main() -> anyhow::Result<()> {
    println!("rustsentry starting up (scaffold — pipeline not yet implemented)");

    // TODO(week 1): open a PcapFileReplay against test-data/pcaps/*.pcap
    let mut replay = PcapFileReplay::new("test-data/pcaps/4SICS-GeekLounge-151020.pcap")?;
    while let Some(frame) = replay.next_frame()? {
        println!("{} bytes", frame.data.len());
    }

    // TODO(week 2): parse::parse_frame() each raw frame
    // TODO(week 3): feed PacketSummary into flow::SlidingWindowCounters
    // TODO(week 6-7): run detect::syn_flood::check() / port_scan::check()
    //                 on a timer and print any Alerts

    Ok(())
}
