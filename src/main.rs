use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkSender;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::icmp;
use pnet::packet::icmp::*;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::env;
use std::net::Ipv4Addr;

fn icmp_packet_reply(
    data: &[u8],
    ipv4packetinfo: IPv4PacketInfo,
    tx: &mut Box<dyn DataLinkSender>,
) {
    // construct icmp packet
    let mut raw_packet: Vec<u8> = vec![0; icmp::MutableIcmpPacket::minimum_packet_size() + data.len()];
    let mut mipacket: MutableIcmpPacket = icmp::MutableIcmpPacket::new(&mut raw_packet).unwrap();
    mipacket.set_payload(data);
    mipacket.set_icmp_type(IcmpTypes::EchoReply);
    mipacket.set_icmp_code(IcmpCode::new(0));
    mipacket.set_checksum(0 as u16);
    mipacket.set_checksum(icmp::checksum(&mipacket.to_immutable()));


    // construct ipv4 packet
    let mut raw_packet: Vec<u8> = vec![0; ipv4::MutableIpv4Packet::minimum_packet_size() + mipacket.packet().len()];
    let mut mi4packet: ipv4::MutableIpv4Packet = ipv4::MutableIpv4Packet::new(&mut raw_packet).unwrap();
    mi4packet.set_version(4); /* version */
    mi4packet.set_header_length(ipv4::Ipv4Packet::minimum_packet_size() as u8); /* Internet Header Length */
    mi4packet.set_header_length(5); /* Internet Header Length */
    mi4packet.set_ecn(24); /* Type of Service */
    mi4packet.set_dscp(24); /* Type of Service */
    mi4packet.set_total_length(mi4packet.packet().len() as u16); /* Total Length */
    mi4packet.set_identification(0); /* Identification */
    mi4packet.set_flags(0); /* Various Control Flags */
    mi4packet.set_fragment_offset(0); /* Fragment Offset */
    mi4packet.set_ttl(115); /* Time to Live */
    mi4packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp); /* Protocol */
    mi4packet.set_checksum(0); /* Header Checksum */
    mi4packet.set_source(ipv4packetinfo.destination); /* Source Address */
    mi4packet.set_destination(ipv4packetinfo.source); /* Destination Address */
    mi4packet.set_checksum(ipv4::checksum(&mi4packet.to_immutable())); /* Header Checksum */
    mi4packet.set_payload(&mut mipacket.packet());


    // construct L2packet
    let mut raw_packet: Vec<u8> = vec![0; MutableEthernetPacket::minimum_packet_size() + mi4packet.packet().len()];
    let mut mepacket = MutableEthernetPacket::new(&mut raw_packet).unwrap();
    mepacket.set_payload(mi4packet.packet());

    mepacket.set_destination(ipv4packetinfo.ehternet_packet_info.as_ref().unwrap().source);
    mepacket.set_source(ipv4packetinfo.ehternet_packet_info.as_ref().unwrap().destination);
    mepacket.set_ethertype(EtherTypes::Ipv4);


    // reply
    tx.send_to(mepacket.packet(), None);
}


// Layer 3
struct IPv4PacketInfo {
    // Layer 3
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ehternet_packet_info: Option<EthernetPacketInfo>
}
// Layer 2
struct EthernetPacketInfo {
    source: MacAddr,
    destination: MacAddr,
}


fn ethernet_packet_check(
    ethernet_packet: &EthernetPacket,
    tx: &mut Box<dyn DataLinkSender>,
){
    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
        let ethernetpacketinfo = EthernetPacketInfo {
            source: ethernet_packet.get_source(),
            destination: ethernet_packet.get_destination(),
        };


        let ipv4packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
        if ipv4packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
            let ipv4packetinfo: IPv4PacketInfo = IPv4PacketInfo {
                source: ipv4packet.get_source(),
                destination: ipv4packet.get_destination(),
                ehternet_packet_info: Some(ethernetpacketinfo),
            };
            
            
            let icmppacket: IcmpPacket = IcmpPacket::new(ipv4packet.payload()).unwrap();
            if icmppacket.get_icmp_type() == IcmpType(8) {
                println!("catch Echo Request : {} -> {}", ipv4packet.get_source(), ipv4packet.get_destination());
                icmp_packet_reply(
                    icmppacket.payload(),
                    ipv4packetinfo,
                    tx,
                );
            }
        }
    }
}


fn main() {
    // set interface
    let mut interface_name: &str = "interface name";
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        interface_name = args[1].as_str();
    }

    let interfaces: Vec<NetworkInterface> = datalink::interfaces()
        .into_iter()
        .filter(|interface: &NetworkInterface| interface_name == interface.name.as_str() )
        .collect();
    
    if interfaces.len() == 0 {
        println!("Interface is Not Found.");
        return;
    }
    let interface: &NetworkInterface = &interfaces[0];
    println!("Interface: {}", interface.name);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(ch) => {
            match ch {
                Ethernet(tx, rx) => (tx, rx),
                _ => panic!("Error occured."),
            }
        }
        Err(e) => {
            panic!("Error occured: {}", e);
        }
    };

    loop {
        match rx.next() {
            Ok(src) => {
                let ehternet_packet = &EthernetPacket::new(src).unwrap();
                ethernet_packet_check(ehternet_packet, &mut tx);
            }
            Err(_) => {
                println!("Error occured in loop.");
                break;
            }
        }
    }
}
