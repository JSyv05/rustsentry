use crate::DetectorConfig;
use flow::{FlowKey, SlidingWindowCounters};
use parser::{PacketSummary, Protocol, TcpFlags};
use std::net::{IpAddr, Ipv4Addr};

pub fn ip(last_octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, last_octet))
}

pub fn sample_key(packet: &PacketSummary) -> FlowKey {
    FlowKey {
        src_ip: packet.src_ip,
        dst_ip: packet.dst_ip,
        protocol: packet.protocol,
    }
}

pub fn record_tcp_packet(counters: &mut SlidingWindowCounters, packet: &PacketSummary) {
    let key = sample_key(packet);
    counters.record(key, packet);
}

pub fn sample_tcp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    tcp_flags: Option<TcpFlags>,
) -> PacketSummary {
    PacketSummary {
        timestamp_micros: 0,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: Protocol::Tcp,
        tcp_flags,
        payload_len: 80,
    }
}

pub fn sample_config(
    window_secs: u64,
    syn_without_ack_threshold: u64,
    distinct_ports_threshold: u64,
    dump_interval_secs: u64,
) -> DetectorConfig {
    DetectorConfig {
        window_secs,
        syn_without_ack_threshold,
        distinct_ports_threshold,
        dump_interval_secs,
    }
}
