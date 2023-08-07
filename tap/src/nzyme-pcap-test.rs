mod ethernet;
mod helpers;
mod brokers;
mod messagebus;
mod link;
mod configuration;
mod exit_code;
mod metrics;
mod processors;
mod data;
mod system_state;
mod logging;
mod dot11;
mod alerting;

use std::panic::catch_unwind;
use std::process::exit;
use std::sync::{Arc, Mutex};
use clap::Parser;
use log::{debug, error, info};
use crate::{
    dot11::frames::Dot11RawFrame,
};
use crate::configuration::Configuration;
use crate::messagebus::bus::Bus;
use crate::brokers::dot11_broker::Dot11Broker;

#[derive(Parser,Debug)]
struct Arguments {
    #[clap(short, long, forbid_empty_values = true)]
    configuration_file: String,

    #[clap(short, long, forbid_empty_values = true)]
    pcap_file: String,

    #[clap(short, long, forbid_empty_values = true)]
    log_level: String
}

fn main() {
    let args = Arguments::parse();

    logging::initialize(&args.log_level);

    let configuration: Configuration = match configuration::load(args.configuration_file) {
        Ok(configuration) => {
            info!("Parsed and loaded configuration.");
            configuration
        },
        Err(e) => {
            error!("Fatal error: Could not load configuration. {}", e);
            exit(exit_code::EX_CONFIG);
        }
    };

    let metrics = Arc::new(Mutex::new(metrics::Metrics::new()));
    let bus = Arc::new(Bus::new(metrics.clone(), "ethernet_packets".to_string(), configuration.clone()));

    info!("Starting nzyme tap version [{}].", env!("CARGO_PKG_VERSION"));

    let mut handle = match pcap::Capture::from_file(args.pcap_file.clone()) {
        Ok(handle) => handle,
        Err(e) => {
            error!("Could not get PCAP capture handle on [{}]: {}", args.pcap_file, e);
            return;
        }
    };

    if let Err(e) = handle.set_datalink(pcap::Linktype::IEEE802_11_RADIOTAP) {
        error!("Could not set datalink type on [{}]: {}", "pcapfile", e);
        return;
    }

    if let Err(e) = handle.filter("", true) {
        error!("Could not set filter on [{}]: {}", "pcapfile", e);
        return;
    }

    //let stats = handle.stats();

    let mut count = 0;
    while let Ok(packet) = handle.next_packet() {
        count += 1;
        if count % 10 == 0 {
            info!("Processed [{}] packets.", count);
        }

        //let length = packet.data.len();

        if packet.data.len() < 4 {
            debug!("Packet too small. Wouldn't even fit radiotap length information. Skipping.");
            continue;
        }

        let data = Arc::new(Dot11RawFrame {
            interface_name: "pcapfile".to_string(),
            data: packet.data.to_vec()
        });

        let handler_result = catch_unwind(|| {
            Dot11Broker::handle(&data, &bus)
        });

        if handler_result.is_err() {
            error!("Unexpected error in frame handling. Skipping.");
        };
    }
}