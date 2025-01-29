use crate::PingResult;
use pnet::packet::icmp::echo_request;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::Packet;
use pnet::transport::TransportSender;
use pnet::util;
use pnet_macros_support::types::*;
use rand::random;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

fn send_echo(tx: &mut TransportSender, addr : IpAddr) -> Result< usize, std::io::Error> {
    let mut vec: Vec<u8> = vec![0; 16];

    let mut echo_packet = echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();
    echo_packet.set_sequence_number(random::<u16>());
    echo_packet.set_identifier(random::<u16>());
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);


    let csum = icmp_checksum(&echo_packet);
    echo_packet.set_checksum(csum);

    tx.send_to(echo_packet, addr)
}

fn send_echov6(tx: &mut TransportSender, addr : IpAddr) -> Result<usize, std::io::Error> {
    let mut vec : Vec<u8> = vec![0; 16];

    let mut echo_packet = MutableIcmpv6Packet::new(&mut vec[..]).unwrap();

    echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);

    let csum = icmpv6_checksum(&echo_packet);

    tx.send_to(echo_packet, addr)
}

pub fn send_pings(
    timer: Arc<RwLock<Instant>>,
    stop:  Arc<Mutex<bool>>,
    results_sender : Sender<PingResult>,
    thread_rx : Arc<Mutex<Receiver<PingResult>>>,
    tx : Arc<Mutex<TransportSender>>,

    txv6 : Arc<Mutex<TransportSender>>,
    addrs : Arc<Mutex<BTreeMap<IpAddr, bool>>>,
    max_rtt : Arc<Duration>,
) {
    loop {
        for(addr, seen) in addrs.lock().unwrap().iter_mut() {
            match if addr.is_ipv4() {
                send_echo(&mut tx.lock().unwrap(),*addr)
            } else if addr.is_ipv6() {
                send_echov6(&mut txv6.lock().unwrap(), *addr)
            } else {
                Ok(0)
            } {
                Err(e) => log::error!("failed to send ping to {:.?}: {}", *addr , e),
                _=> {}
            }
            *seen = false;
        }
        {
            let mut timer = timer.write().unwrap();
            *timer = Instant::now();
        }

        loop {
            match thread_rx.lock().unwrap().recv_timeout(Duration::from_millis(100))
            {
                Ok(result) => {
                    match result {
                        PingResult::Receive{addr , rtt:_ } => {
                            if let Some(seen) = addrs.lock().unwrap().get_mut(&addr) {
                                *seen = true;


                                match results_sender.send(result) {
                                    Ok(_) => {},
                                    Err(e) => {
                                        if !*stop.lock().unwrap() {
                                            log::error!{
                                                "Error Sending ping result on channel: {}",
                                                e
                                            }
                                        }
                                    }
                                }

                            }

                        }
                        _=> {}
                    }
                }

                Err(_) => {
                    let start_time = timer.read().unwrap();
                    if Instant::now().duration_since(*start_time) > *max_rtt {
                        break;
                    }
                }
            }
        }
        for (addr, seen) in addrs.lock().unwrap().iter() {
            if *seen == false {
                match results_sender.send(PingResult::Idle{addr : *addr}) {
                    Ok(_) => {}
                    Err(e) => {
                        if !*stop.lock().unwrap() {
                            log::error!("Error sending ping Idle result on channel: {}", e)
                        }
                    }
                }
            }
        }
        if *stop.lock().unwrap() {
            return;
        }

    }

}

fn icmp_checksum(packet: &echo_request::MutableEchoRequestPacket) -> u16be {
    util::checksum(packet.packet(), 1)
}

fn icmpv6_checksum(packet: &MutableIcmpv6Packet) -> u16be {
    util::checksum(packet.packet(), 1)
}