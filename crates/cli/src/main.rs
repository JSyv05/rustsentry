//! Entry point: wires capture -> parser -> flow -> detect together and
//! prints/logs alerts. Week 1 goal: this compiles and runs, even if every
//! stage below it is still a todo!().
use anyhow::Context;
use capture::{FrameEvent, FrameSource, LiveCapture, PcapFileReplay};
use chrono::DateTime;
use clap::Parser;
use detect::DetectorConfig;
use flow::{FlowKey, SlidingWindowCounters};
use parser::MICROS_PER_SEC;
use std::fs;
use std::time::{Duration, Instant, SystemTime};

const SYSTEM_CONFIG: &str = "/etc/rustsentry/thresholds.toml";
const DEFAULT_CONFIG: &str = include_str!("../../../config/thresholds.toml");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    list_devices: bool,

    #[arg(
        long = "live",
        value_name = "DEVICE",
        require_equals = true,
        conflicts_with = "pcap"
    )]
    live: Option<Option<String>>,

    #[arg(long = "config", value_name = "PATH_TO_CONFIG")]
    path: Option<String>,

    #[arg(value_name = "PATH_TO_PCAP")]
    pcap: Option<String>,
}

fn load_config(explicit: Option<&str>) -> anyhow::Result<DetectorConfig> {
    let (text, source) = match explicit {
        Some(path) => (
            fs::read_to_string(path).with_context(|| format!("reading config {path}"))?,
            path,
        ),
        None => match fs::read_to_string(SYSTEM_CONFIG) {
            Ok(text) => (text, SYSTEM_CONFIG),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("no config at {SYSTEM_CONFIG}, using built-in defaults");
                (DEFAULT_CONFIG.to_string(), "built-in defaults")
            }
            Err(e) => {
                return Err(e).with_context(|| format!("reading config {SYSTEM_CONFIG}"));
            }
        },
    };
    toml::from_str(&text).with_context(|| format!("parsing config ({source})"))
}

fn is_due(dump_micros: &mut Option<i64>, dump_interval: i64, now_micros: i64) -> bool {
    let due = *dump_micros.get_or_insert(now_micros + dump_interval);
    if now_micros >= due {
        *dump_micros = Some(due + dump_interval); // or current_micros + dump_interval
        true
    } else {
        false
    }
}

fn dump(counter: &SlidingWindowCounters, now_micros: i64) {
    let readable = DateTime::from_timestamp_micros(now_micros)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string())
        .unwrap_or_else(|| now_micros.to_string());

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

fn tick(counters: &mut SlidingWindowCounters, cfg: &DetectorConfig, now_micros: i64) {
    dump(counters, now_micros);
    for alert in detect::syn_flood::check(counters, cfg, now_micros) {
        println!("{alert:?}");
    }
    for alert in detect::port_scan::check(counters, cfg, now_micros) {
        println!("{alert:?}");
    }
    counters.evict_stale(now_micros);
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.list_devices {
        for device in capture::list_devices()? {
            println!(
                "{}\t{}",
                device.name,
                device.desc.as_deref().unwrap_or("(no description)")
            );
        }
        return Ok(());
    }

    let mut source: Box<dyn FrameSource> = match args.live {
        Some(None) => Box::new(LiveCapture::new()?),

        Some(Some(arg)) => Box::new(LiveCapture::on_device(&arg)?),

        None => match args.pcap {
            Some(path) => Box::new(PcapFileReplay::new(path)?),
            None => anyhow::bail!("no input source: pass --live[=DEVICE] or a PCAP path"),
        },
    };

    let cfg = load_config(args.path.as_deref())?;

    let dump_interval_micros: i64 = cfg.dump_interval_secs as i64 * MICROS_PER_SEC;
    let mut next_dump_micros: Option<i64> = None;

    let mut last_tick = Instant::now();
    let tick_interval = Duration::from_secs(cfg.dump_interval_secs);

    println!("rustsentry starting up");

    let mut counters = SlidingWindowCounters::new(cfg.window_secs);
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
                        tick(&mut counters, &cfg, summary.timestamp_micros);
                    }
                }
            }
            FrameEvent::Timeout => {
                if last_tick.elapsed() >= tick_interval {
                    last_tick = Instant::now();
                    let now_micros = SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_micros() as i64;

                    if is_due(&mut next_dump_micros, dump_interval_micros, now_micros) {
                        tick(&mut counters, &cfg, now_micros);
                    }
                }
            }
            FrameEvent::Eof => break,
        };
    }

    Ok(())
}
