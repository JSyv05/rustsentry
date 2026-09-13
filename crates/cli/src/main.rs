//! Entry point: wires capture -> parser -> flow -> detect together and
//! prints/logs alerts. Week 1 goal: this compiles and runs, even if every
//! stage below it is still a todo!().

use capture::{FrameSource, LiveCapture, PcapFileReplay};
use flow::{FlowKey, SlidingWindowCounters};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(String::as_str) == Some("--list-devices") {
        for device in capture::list_devices()? {
            println!(
                "{}\t{}",
                device.name,
                device.desc.as_deref().unwrap_or("(no description)")
            );
        }
        return Ok(());
    }

    let dump_interval_micros: i64 = 5_000_000; // 5s, based on packet time. to be controlled by config
    let mut next_dump_micros: Option<i64> = None;

    let mut source: Box<dyn FrameSource> = match args.get(1).map(String::as_str) {
        Some("--live") => Box::new(LiveCapture::new()?),

        Some(arg) if arg.starts_with("--live=") => {
            Box::new(LiveCapture::on_device(&arg["--live=".len()..])?)
        }
        Some(path) => Box::new(PcapFileReplay::new(path)?),
        None => Box::new(PcapFileReplay::new(
            "test-data/pcaps/4SICS-GeekLounge-151020.pcap",
        )?),
    };

    println!("rustsentry starting up");

    let mut counters = SlidingWindowCounters::new(10); // TODO! use config/threshold.toml for config
    while let Some(frame) = source.next_frame()? {
        if let Some(summary) = parser::parse_frame(&frame.data, frame.timestamp_micros) {
            let key = FlowKey {
                src_ip: summary.src_ip,
                dst_ip: summary.dst_ip,
                protocol: summary.protocol,
            };

            counters.record(key, &summary);

            let due =
                *next_dump_micros.get_or_insert(summary.timestamp_micros + dump_interval_micros);
            if summary.timestamp_micros >= due {
                println!("--- flow table @ {} ---", summary.timestamp_micros);
                for flow in counters.flows() {
                    println!(
                        "{} -> {} [{:?}]: {} pkts, {} bytes, {} syn, {} ack, {} dst ports",
                        flow.key.src_ip,
                        flow.key.dst_ip,
                        flow.key.protocol,
                        flow.packet_count,
                        flow.byte_count,
                        flow.syn_count,
                        flow.ack_count,
                        flow.distinct_dst_ports
                    );
                }
                next_dump_micros = Some(due + dump_interval_micros);
            }
        }
    }

    // TODO(week 6-7): run detect::syn_flood::check() / port_scan::check()
    //                 on a timer and print any Alerts

    Ok(())
}
