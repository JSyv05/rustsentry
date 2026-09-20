//! Entry point: wires capture -> parser -> flow -> detect together and
//! prints/logs alerts. Week 1 goal: this compiles and runs, even if every
//! stage below it is still a todo!().

use capture::{FrameEvent, FrameSource, LiveCapture, PcapFileReplay};
use chrono::DateTime;
use flow::{FlowKey, SlidingWindowCounters};
use std::time::{Duration, Instant, SystemTime};

fn is_due(dump_micros: &mut Option<i64>, dump_interval: i64, current_micros: i64) -> bool {
    let due = *dump_micros.get_or_insert(current_micros + dump_interval);
    if current_micros >= due {
        *dump_micros = Some(due + dump_interval); // or current_micros + dump_interval
        true
    } else {
        false
    }
}

fn dump(counter: &SlidingWindowCounters, current_micros: i64) {
    let readable = DateTime::from_timestamp_micros(current_micros)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string())
        .unwrap_or_else(|| current_micros.to_string());

    println!("--- flow table @ {} ---", readable);
    for flow in counter.flows() {
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
}

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

    let mut last_tick = Instant::now();
    let tick_interval = Duration::from_secs(5);

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
    loop {
        match source.next_frame()? {
            FrameEvent::Frame(frame) => {
                if let Some(summary) = parser::parse_frame(&frame.data, frame.timestamp_micros) {
                    let key = FlowKey {
                        src_ip: summary.src_ip,
                        dst_ip: summary.dst_ip,
                        protocol: summary.protocol,
                    };

                    counters.record(key, &summary);

                    if is_due(
                        &mut next_dump_micros,
                        dump_interval_micros,
                        summary.timestamp_micros,
                    ) {
                        dump(&counters, summary.timestamp_micros);

                        counters.evict_stale(summary.timestamp_micros);
                    }
                }
            }
            // TODO(week 5): use this to run wall-clock-driven eviction/dump
            // for live mode during idle traffic (see DECISIONS.md 09/17).
            FrameEvent::Timeout => {
                if last_tick.elapsed() >= tick_interval {
                    last_tick = Instant::now();
                    let now_micros = SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_micros() as i64;

                    if is_due(&mut next_dump_micros, dump_interval_micros, now_micros) {
                        dump(&counters, now_micros);

                        counters.evict_stale(now_micros);
                    }
                }
            }
            FrameEvent::Eof => break,
        };
    }

    // TODO(week 6-7): run detect::syn_flood::check() / port_scan::check()
    //                 on a timer and print any Alerts

    Ok(())
}
