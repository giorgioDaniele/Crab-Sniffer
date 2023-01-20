use std::env::args;

mod arp;
mod ethernet;
mod ip;
mod icmp;
mod udp_tcp;


fn open_interface(iface: pcap::Device) {
    match pcap::Capture::from_device(iface) {
        Ok(sniffer) => match sniffer.promisc(true).immediate_mode(true).open() {
            Ok(mut sniffer) => {

                while let Ok(packet) = sniffer.next_packet() {
                    let a_sec = std::time::Duration::from_secs(1);
                    std::thread::sleep(a_sec);
                    show_packet(&packet);
                }
            }
            Err(error) => println!("{}", error),
        },
        Err(error) => println!("{}", error),
    }
}
fn mac_address(mac: [u8; 6]) -> String {
    eui48::MacAddress::new(mac).to_hex_string().to_uppercase()
}
fn ip_address(ip: [u8; 4]) -> String {
    std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string()
}
fn parse_arp(packet: &pdu::EthernetPdu) {

    match packet.inner() {
        Ok(pdu::Ethernet::Arp(arp)) => {
            println!("-------------------------------------------------------------------------------------");

            match arp::ARP::HardwareType::from(arp.hardware_type()) {
                arp::ARP::HardwareType::RESERVED(_) => println!("        # Hardware Type:    RESERVED"),
                arp::ARP::HardwareType::ETHERNET(_) => println!("        # Hardware Type:    ETHERNET"),
                arp::ARP::HardwareType::IEE802(_) => println!("        # Hardware Type:    IEE802"),
                arp::ARP::HardwareType::FRAME_RELAY(_) => println!("        # Hardware Type:    FRAMERELAY"),
                arp::ARP::HardwareType::UNKNOWN(_) => println!("        # Hardware Type:    UNKNOWN"),
            }
            println!("        # Protocol Type:    IPv4");
            println!("        # HLEN:             {}", arp.hardware_length());
            println!("        # LEN:              {}", arp.protocol_length());
            match arp::ARP::OperationCode::from(arp.opcode()) {
                arp::ARP::OperationCode::REQUEST(_) => {
                    println!("        # Opertion Code:    REQUEST");
                    match (arp::ARP::HardwareType::from(arp.hardware_type()), ethernet::ETHERNET::EtherType::from(arp.protocol_type())) {
                        (arp::ARP::HardwareType::ETHERNET(_), ethernet::ETHERNET::EtherType::IPV4(_)) => {
                            println!("        # Who is {}? I'm IP {} with MAC {}", 
                                ip_address(arp.target_protocol_address()), 
                                ip_address(arp.sender_protocol_address()), 
                                mac_address(arp.sender_hardware_address()));
                        },
                        _ => {},
                    }
                },
                arp::ARP::OperationCode::REPLAY(_) => {
                    println!("        # Opertion Code:    REPLAY");
                    match (arp::ARP::HardwareType::from(arp.hardware_type()), ethernet::ETHERNET::EtherType::from(arp.protocol_type())) {
                        (arp::ARP::HardwareType::ETHERNET(_), ethernet::ETHERNET::EtherType::IPV4(_)) => {
                            println!("        # Hi, I'm IP {} with MAC {}", 
                            ip_address(arp.sender_protocol_address()), 
                            mac_address(arp.sender_hardware_address()));
                        },
                        _ => {},
                    }
                },
                arp::ARP::OperationCode::UNKNOWN(_) => todo!(),
            }
        },
        Ok(_) => {},
        Err(error) => println!("{}", error),
    }
}
fn parse_ipv4(packet: &pdu::EthernetPdu) {
    match packet.inner() {
        Ok(pdu::Ethernet::Ipv4(ipv4)) => {
            println!("-------------------------------------------------------------------------------------");
             
            print!(
                "From:   {}  To:  {}    Protocol: 0x{:x} ",
                ip_address(ipv4.source_address()),
                ip_address(ipv4.destination_address()),
                ipv4.protocol()
            );
            match ip::IP::Protocol::from(ipv4.protocol()) {
                ip::IP::Protocol::TCP(_) => println!("(TCP)"),
                ip::IP::Protocol::UDP(_) => println!("(UDP)"),
                ip::IP::Protocol::ICMP(_) => println!("(ICMP)"),
                ip::IP::Protocol::UNKNOWN(_) => println!("(Unknown)"),
            }
            println!("        # Version:    {}", ipv4.version());
            println!("        # IHL:        {}", ipv4.computed_ihl());
            println!("        # TTL:        {} (max 255)", ipv4.ttl());
            println!("        # Checksum:   {}", ipv4.checksum());
            println!("        # Tot Length: {}", ipv4.total_length());
            
            match ip::IP::Protocol::from(ipv4.protocol()) {
                ip::IP::Protocol::TCP(_) => parse_tcp(&ipv4),
                ip::IP::Protocol::UDP(_) => parse_udp(&ipv4),
                ip::IP::Protocol::ICMP(_) => parse_icmp(&ipv4),
                ip::IP::Protocol::UNKNOWN(_) => {}
            }
        }
        Ok(_) => {}
        Err(error) => println!("{}", error),
    }
}
fn parse_icmp(packet: & pdu::Ipv4Pdu) {

    println!("-------------------------------------------------------------------------------------");
    match packet.inner() {
        Ok(pdu::Ipv4::Icmp(icmp)) => {
            match icmp::ICMP::Type::from(icmp.message_type()){
                icmp::ICMP::Type::REQUEST(_) => println!("        # PING"),
                icmp::ICMP::Type::REPLY(_) => println!("        # PONG"),
                icmp::ICMP::Type::UNKNOWN(_) => {},
            }
            println!("        # Checksum: {}", icmp.checksum());
        },
        Ok(_) => {},
        Err(error) => println!("{}", error),
    }

}
fn parse_tcp(packet: & pdu::Ipv4Pdu) {
    
    println!("-------------------------------------------------------------------------------------");
    match packet.inner() {
        Ok(pdu::Ipv4::Tcp(tcp)) => {
    
            match udp_tcp::UDP_TCP::Port::from(tcp.source_port()) {
                udp_tcp::UDP_TCP::Port::HTTP(_) => print!("        # Src Port: {} (HTTP) ", tcp.source_port()),
                udp_tcp::UDP_TCP::Port::HTTPS(_) => print!("        # Src Port: {} (HTTPS) ", tcp.source_port()),
                udp_tcp::UDP_TCP::Port::DHCP_1(_) => print!("        # Src Port: {} (DHCP) ", tcp.source_port()),
                udp_tcp::UDP_TCP::Port::DHCP_2(_) => print!("        # Src Port: {} (DHCP) ", tcp.source_port()),
                udp_tcp::UDP_TCP::Port::DNS(_) => print!("        # Src Port: {} (DNS) ", tcp.source_port()),
                udp_tcp::UDP_TCP::Port::UNKNOWN(_) => print!("        # Src Port: {} ", tcp.source_port()),
            }
            match udp_tcp::UDP_TCP::Port::from(tcp.destination_port()) {
                udp_tcp::UDP_TCP::Port::HTTP(_) => println!("Dst Port: {} (HTTP) ", tcp.destination_port()),
                udp_tcp::UDP_TCP::Port::HTTPS(_) => println!("Dst Port: {} (HTTPS) ", tcp.destination_port()),
                udp_tcp::UDP_TCP::Port::DHCP_1(_) => println!("Dst Port: {} (DHCP) ", tcp.destination_port()),
                udp_tcp::UDP_TCP::Port::DHCP_2(_) => println!("Dst Port: {} (DHCP) ", tcp.destination_port()),
                udp_tcp::UDP_TCP::Port::DNS(_) => println!("Dst Port: {} (DNS) ", tcp.destination_port()),
                udp_tcp::UDP_TCP::Port::UNKNOWN(_) => println!("Dst Port: {} ", tcp.destination_port()),
            }
            println!("        # Seq Numb: {}", tcp.sequence_number());
            println!("        # Ack Numb: {}", tcp.acknowledgement_number());
            println!("        # Window:   {}", tcp.window_size());
            println!("        # Checksum: {}", tcp.checksum());
            // URG ACK PSH RST SYN FIN
            println!("        # URG: {}", (tcp.flags() & 0b100000) >> 5);
            println!("        # ACK: {}", (tcp.flags() & 0b010000) >> 4);
            println!("        # PSH: {}", (tcp.flags() & 0b001000) >> 3);
            println!("        # RST: {}", (tcp.flags() & 0b000100) >> 2);
            println!("        # SYN: {}", (tcp.flags() & 0b000010) >> 1);
            println!("        # FIN: {}", (tcp.flags() & 0b000001));
        
        }
        Ok(_) => {},
        Err(error) => println!("{}", error),
    }
}
fn parse_udp(packet : & pdu::Ipv4Pdu) {

    println!("-------------------------------------------------------------------------------------");
    match packet.inner() {
        Ok(pdu::Ipv4::Udp(udp)) => {

            match udp_tcp::UDP_TCP::Port::from(udp.source_port()) {
                udp_tcp::UDP_TCP::Port::HTTP(_) => print!("        # Src Port: {} (HTTP) ", udp.source_port()),
                udp_tcp::UDP_TCP::Port::HTTPS(_) => print!("        # Src Port: {} (HTTPS) ", udp.source_port()),
                udp_tcp::UDP_TCP::Port::DHCP_1(_) => print!("        # Src Port: {} (DHCP) ", udp.source_port()),
                udp_tcp::UDP_TCP::Port::DHCP_2(_) => print!("        # Src Port: {} (DHCP) ", udp.source_port()),
                udp_tcp::UDP_TCP::Port::DNS(_) => print!("        # Src Port: {} (DNS) ", udp.source_port()),
                udp_tcp::UDP_TCP::Port::UNKNOWN(_) => print!("        # Src Port: {} ", udp.source_port()),
            }
            match udp_tcp::UDP_TCP::Port::from(udp.destination_port()) {
                udp_tcp::UDP_TCP::Port::HTTP(_) => println!("Dst Port: {} (HTTP) ", udp.destination_port()),
                udp_tcp::UDP_TCP::Port::HTTPS(_) => println!("Dst Port: {} (HTTPS) ", udp.destination_port()),
                udp_tcp::UDP_TCP::Port::DHCP_1(_) => println!("Dst Port: {} (DHCP) ", udp.destination_port()),
                udp_tcp::UDP_TCP::Port::DHCP_2(_) => println!("Dst Port: {} (DHCP) ", udp.destination_port()),
                udp_tcp::UDP_TCP::Port::DNS(_) => println!("Dst Port: {} (DNS) ", udp.destination_port()),
                udp_tcp::UDP_TCP::Port::UNKNOWN(_) => println!("Dst Port: {} ", udp.destination_port()),
            }            
            println!("        # Length:   {}", udp.length());
            println!("        # Checksum: {}", udp.checksum());
            match udp_tcp::UDP_TCP::Port::from(udp.source_port()) {
                udp_tcp::UDP_TCP::Port::DNS(_) => parse_dns(&udp),
                _ => {},
            }
            match udp_tcp::UDP_TCP::Port::from(udp.destination_port()) {
                udp_tcp::UDP_TCP::Port::DNS(_) => parse_dns(&udp),
                _ => {},
            }
        }
        Ok(_) => {},
        Err(error) => println!("{}", error),
    }

}
fn parse_dns(udp: & pdu::UdpPdu) {

    println!("-------------------------------------------------------------------------------------");
    match udp.inner() {
        Ok(pdu::Udp::Raw(packet)) => {
            if let Ok(dns) = dns_parser::Packet::parse(packet) {
                let header = dns.header;
                println!("        # Identification:   {}", header.id);
                if header.query {   
                    println!("        # DNS Query");
                    dns.questions.iter().enumerate().for_each(|(id, question)| {
                        println!("        # Question No°{} {}", id + 1, question.qname.to_string());
                    });
                }
                else {
                    println!("        # DNS Reply"); 
                    dns.answers.iter().enumerate().for_each(|(_, answer)| {
                        match answer.data { 
                            dns_parser::RData::A(record) =>     println!("        # {} IPv4  {}", answer.name, record.0.to_string()),
                            dns_parser::RData::AAAA(record) =>  println!("        # {} IPv6  {}", answer.name, record.0.to_string()),
                            dns_parser::RData::CNAME(record) => println!("        # {} CNAME {}", answer.name, record.0.to_string()),
                            _ => println!(""),
                            
                        }
                    });
                }
            }
        },
        Err(error) => println!("{}", error), 
    }
}


fn show_packet(packet: &pcap::Packet) {
    println!("-------------------------------------------------------------------------------------");
    match pdu::EthernetPdu::new(packet.data) {
        Ok(eth) => {
            print!(
                "From:   {}  To:  {}    Ethertype: 0x{:x} ",
                mac_address(eth.source_address()),
                mac_address(eth.destination_address()),
                eth.ethertype()
            );

            match ethernet::ETHERNET::EtherType::from(eth.ethertype()) {
                ethernet::ETHERNET::EtherType::ARP(_) => {
                    println!("(ARP)");
                    parse_arp(&eth);
                }
                ethernet::ETHERNET::EtherType::IPV4(_) => {
                    println!("(IPv4)");
                    parse_ipv4(&eth);
                }
                ethernet::ETHERNET::EtherType::IPV6(_) => {
                    println!("(IPv6)");
                }
                ethernet::ETHERNET::EtherType::UNKNOWN(_) => println!(""),
            }
        }
        Err(error) => println!("{}", error),
    }
    println!(
        "-------------------------------------------------------------------------------------\n\n"
    );
}

fn main() {


    println!("\n\n");
    println!("############  Welcome to crab-sniffer ############");
    println!("Support for:  [ARP] [ICMP] [UDP] [TCP]");
    let a_sec = std::time::Duration::from_secs(1);
    std::thread::sleep(a_sec); 

    println!("\n\n");


    match pcap::Device::lookup() {
        Ok(iface) => match iface {
            Some(iface) => open_interface(iface),
            None => println!("[ERROR]: cannot sniff anything"),
        },
        Err(error) => println!("{}", error),
    }
}


