//! Entry point: wires capture -> parser -> flow -> detect together and
//! prints/logs alerts. Week 1 goal: this compiles and runs, even if every
//! stage below it is still a todo!().
use anyhow::Context;
use capture::{FrameEvent, FrameSource, LiveCapture, PcapFileReplay};
use chrono::DateTime;
use clap::Parser;
use detect::{Alert, DetectorConfig};
use flow::{FlowKey, SlidingWindowCounters};
use parser::MICROS_PER_SEC;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
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

    #[arg(long = "alert-log", value_name = "PATH")]
    alert_log: Option<PathBuf>,
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
                tracing::info!("no config at {SYSTEM_CONFIG}, using built-in defaults");
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

    tracing::debug!("--- flow table @ {} ---", readable);
    for flow in counter.flows() {
        tracing::debug!(
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

fn write_alerts(out: &mut dyn Write, alerts: Vec<Alert>) -> anyhow::Result<()> {
    for alert in alerts {
        let mut line = serde_json::to_string(&alert)?;
        line.push('\n');
        out.write_all(line.as_bytes())?;
    }
    Ok(())
}

fn tick(
    counters: &mut SlidingWindowCounters,
    cfg: &DetectorConfig,
    now_micros: i64,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    counters.evict_stale(now_micros);
    dump(counters, now_micros);
    write_alerts(out, detect::syn_flood::check(counters, cfg, now_micros))?;
    write_alerts(out, detect::port_scan::check(counters, cfg, now_micros))?;
    out.flush()?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
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

    let mut alert_out: Box<dyn Write> = match &args.alert_log {
        Some(path) => Box::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening alert log {}", path.display()))?,
        ),
        None => Box::new(std::io::stdout()),
    };

    tracing::info!("rustsentry starting up");

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
                        tick(
                            &mut counters,
                            &cfg,
                            summary.timestamp_micros,
                            &mut *alert_out,
                        )?;
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
                        tick(&mut counters, &cfg, now_micros, &mut *alert_out)?;
                    }
                }
            }
            FrameEvent::Eof => break,
        };
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use detect::AlertKind;
    use std::net::{IpAddr, Ipv4Addr};

    fn alert(kind: AlertKind, last_octet: u8, at: i64) -> Alert {
        Alert {
            kind,
            target: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)),
            detected_at_micros: at,
            detail: "detail".to_string(),
        }
    }

    #[test]
    fn write_alerts_emits_one_json_line_per_alert() {
        let alerts = vec![
            alert(AlertKind::SynFlood, 2, 42),
            alert(AlertKind::PortScan, 3, 43),
        ];
        let mut out = Vec::new();

        write_alerts(&mut out, alerts).unwrap();

        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["kind"], "SynFlood");
        assert_eq!(first["target"], "10.0.0.2");
        assert_eq!(first["detected_at_micros"], 42);

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["kind"], "PortScan");
        assert_eq!(second["target"], "10.0.0.3");
    }

    #[test]
    fn write_alerts_with_no_alerts_writes_nothing() {
        let mut out = Vec::new();
        write_alerts(&mut out, Vec::new()).unwrap();
        assert!(out.is_empty());
    }
}
