package com.dpi.parser;

import com.dpi.model.PacketInfo;
import org.pcap4j.packet.*;

public class PacketParser {

    /**
     * Parses a raw Pcap4J Packet into our normalized PacketInfo domain model.
     * 
     * @param packet The raw packet from Pcap4J.
     * @return A parsed, normalized PacketInfo object.
     */
    public static PacketInfo parse(Packet packet) {
        PacketInfo.Builder builder = new PacketInfo.Builder();
        
        // Extract timestamp if available
        builder.timestamp(System.currentTimeMillis());

        builder.packetLength(packet.length());

        // Extract Link Layer (Ethernet)
        EthernetPacket ethPacket = packet.get(EthernetPacket.class);
        if (ethPacket != null) {
            builder.srcMac(ethPacket.getHeader().getSrcAddr().toString());
            builder.dstMac(ethPacket.getHeader().getDstAddr().toString());
        }

        // Extract Network Layer (IPv4 / IPv6)
        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        IpV6Packet ipv6 = packet.get(IpV6Packet.class);

        if (ipv4 != null) {
            builder.srcIp(ipv4.getHeader().getSrcAddr().getHostAddress());
            builder.dstIp(ipv4.getHeader().getDstAddr().getHostAddress());
            builder.ttl(ipv4.getHeader().getTtlAsInt());
            builder.protocol("IPv4"); // Default, will be overridden if transport layer found
        } else if (ipv6 != null) {
            builder.srcIp(ipv6.getHeader().getSrcAddr().getHostAddress());
            builder.dstIp(ipv6.getHeader().getDstAddr().getHostAddress());
            builder.ttl(ipv6.getHeader().getHopLimitAsInt());
            builder.protocol("IPv6"); // Default, will be overridden if transport layer found
        }

        // Extract Transport Layer (TCP, UDP, ICMP)
        TcpPacket tcp = packet.get(TcpPacket.class);
        UdpPacket udp = packet.get(UdpPacket.class);
        IcmpV4CommonPacket icmpV4 = packet.get(IcmpV4CommonPacket.class);
        IcmpV6CommonPacket icmpV6 = packet.get(IcmpV6CommonPacket.class);

        if (tcp != null) {
            builder.protocol("TCP");
            builder.srcPort(tcp.getHeader().getSrcPort().valueAsInt());
            builder.dstPort(tcp.getHeader().getDstPort().valueAsInt());

            int flags = 0;
            TcpPacket.TcpHeader th = tcp.getHeader();
            if (th.getUrg()) flags |= 0x20;
            if (th.getAck()) flags |= 0x10;
            if (th.getPsh()) flags |= 0x08;
            if (th.getRst()) flags |= 0x04;
            if (th.getSyn()) flags |= 0x02;
            if (th.getFin()) flags |= 0x01;
            builder.tcpFlags(flags);

            if (tcp.getPayload() != null) {
                builder.payloadLength(tcp.getPayload().length());
                builder.payload(tcp.getPayload().getRawData());
            } else {
                builder.payloadLength(0);
                builder.payload(new byte[0]);
            }
        } else if (udp != null) {
            builder.protocol("UDP");
            builder.srcPort(udp.getHeader().getSrcPort().valueAsInt());
            builder.dstPort(udp.getHeader().getDstPort().valueAsInt());

            if (udp.getPayload() != null) {
                builder.payloadLength(udp.getPayload().length());
                builder.payload(udp.getPayload().getRawData());
            } else {
                builder.payloadLength(0);
                builder.payload(new byte[0]);
            }
        } else if (icmpV4 != null) {
            builder.protocol("ICMP");
            if (icmpV4.getPayload() != null) {
                builder.payloadLength(icmpV4.getPayload().length());
                builder.payload(icmpV4.getPayload().getRawData());
            }
        } else if (icmpV6 != null) {
            builder.protocol("ICMPv6");
            if (icmpV6.getPayload() != null) {
                builder.payloadLength(icmpV6.getPayload().length());
                builder.payload(icmpV6.getPayload().getRawData());
            }
        }

        builder.rawPacket(packet);

        return builder.build();
    }
}
