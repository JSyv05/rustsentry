//! Entry point: wires capture -> parser -> flow -> detect together and
//! prints/logs alerts. Week 1 goal: this compiles and runs, even if every
//! stage below it is still a todo!().

use capture::{FrameSource, PcapFileReplay};
use flow::{FlowKey, SlidingWindowCounters};

fn main() -> anyhow::Result<()> {
    println!("rustsentry starting up (scaffold — pipeline not yet implemented)");

    let mut replay = PcapFileReplay::new("test-data/pcaps/4SICS-GeekLounge-151020.pcap")?;
    let mut counters = SlidingWindowCounters::new(10); // TODO! use config/threshold.toml for config
    while let Some(frame) = replay.next_frame()? {
        println!("{} bytes", frame.data.len());

        if let Some(summary) = parser::parse_frame(&frame.data, frame.timestamp_micros) {
            let key = FlowKey {
                src_ip: summary.src_ip,
                dst_ip: summary.dst_ip,
                protocol: summary.protocol,
            };

            counters.record(key, &summary);

            println!(
                "{} -> {}, {:?}",
                summary.src_ip, summary.dst_ip, summary.protocol
            );

            println!("{} flows tracked", counters.flow_count());
        }
    }

    // TODO(week 6-7): run detect::syn_flood::check() / port_scan::check()
    //                 on a timer and print any Alerts

    Ok(())
}
