package com.dpi.pcap;

import com.dpi.capture.PcapFileSource;
import com.dpi.model.PacketInfo;
import com.dpi.parser.PacketParser;
import org.junit.jupiter.api.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class SamplePcapGeneratorTest {

    private static final MacAddress SRC_MAC = MacAddress.getByName("02:00:00:00:00:01");
    private static final MacAddress DST_MAC = MacAddress.getByName("02:00:00:00:00:02");

    @Test
    public void testGenerateAndParseSamplePcap() throws Exception {
        String pcapPath = "pcaps/input/sample.pcap";
        File dir = new File("pcaps/input");
        if (!dir.exists()) {
            dir.mkdirs();
        }

        List<Packet> packets = new ArrayList<>();

        // 1. DNS Query Packet
        byte[] dnsPayload = createDnsQueryPayload("example.com");
        packets.add(buildUdpPacket("192.168.1.50", "8.8.8.8", 53000, 53, dnsPayload));

        // 2. HTTP Request Packet
        String httpPayloadStr = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: DPI-Test/1.0\r\n\r\n";
        packets.add(buildTcpPacket("192.168.1.50", "93.184.216.34", 49152, 80, (short) 0x18, httpPayloadStr.getBytes(StandardCharsets.UTF_8))); // PSH, ACK

        // 3. TLS ClientHello Packet
        byte[] tlsPayload = createTlsClientHelloPayload("google.com");
        packets.add(buildTcpPacket("192.168.1.50", "142.250.190.46", 49153, 443, (short) 0x18, tlsPayload));

        // 4. Port Scan Packets (SYN to 25 ports from 10.0.0.99)
        for (int p = 20; p <= 45; p++) {
            packets.add(buildTcpPacket("10.0.0.99", "192.168.1.1", 40000 + p, p, (short) 0x02, new byte[0])); // SYN
        }

        // Dump to PCAP
        PcapHandle deadHandle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
        PcapDumper dumper = deadHandle.dumpOpen(pcapPath);
        for (Packet pkt : packets) {
            dumper.dump(pkt);
        }
        dumper.close();
        deadHandle.close();

        File pcapFile = new File(pcapPath);
        assertTrue(pcapFile.exists() && pcapFile.length() > 0, "PCAP file must exist and be non-empty");

        // Verify with PcapFileSource and PacketParser
        PcapFileSource source = new PcapFileSource(pcapPath);
        AtomicInteger parsedCount = new AtomicInteger(0);

        source.start(rawPacket -> {
            PacketInfo info = PacketParser.parse(rawPacket);
            assertNotNull(info);
            assertNotNull(info.getRawPacket(), "rawPacket must be populated in PacketInfo");
            assertNotNull(info.getSrcIp());
            assertNotNull(info.getDstIp());
            parsedCount.incrementAndGet();
        });
        source.close();

        assertEquals(packets.size(), parsedCount.get(), "All dumped packets must be successfully parsed");
    }

    private static Packet buildTcpPacket(String srcIp, String dstIp, int srcPort, int dstPort, short flags, byte[] payload) throws Exception {
        Inet4Address srcInet = (Inet4Address) InetAddress.getByName(srcIp);
        Inet4Address dstInet = (Inet4Address) InetAddress.getByName(dstIp);

        TcpPacket.Builder tcp = new TcpPacket.Builder();
        tcp.srcPort(TcpPort.getInstance((short) srcPort))
           .dstPort(TcpPort.getInstance((short) dstPort))
           .srcAddr(srcInet)
           .dstAddr(dstInet)
           .sequenceNumber(1000)
           .acknowledgmentNumber(0)
           .syn((flags & 0x02) != 0)
           .ack((flags & 0x10) != 0)
           .psh((flags & 0x08) != 0)
           .rst((flags & 0x04) != 0)
           .fin((flags & 0x01) != 0)
           .urg((flags & 0x20) != 0)
           .window((short) 65535)
           .correctChecksumAtBuild(true)
           .correctLengthAtBuild(true)
           .payloadBuilder(new UnknownPacket.Builder().rawData(payload));

        IpV4Packet.Builder ip = new IpV4Packet.Builder();
        ip.version(IpVersion.IPV4)
          .tos(IpV4Rfc791Tos.newInstance((byte) 0))
          .ttl((byte) 64)
          .protocol(IpNumber.TCP)
          .srcAddr(srcInet)
          .dstAddr(dstInet)
          .correctChecksumAtBuild(true)
          .correctLengthAtBuild(true)
          .payloadBuilder(tcp);

        EthernetPacket.Builder ether = new EthernetPacket.Builder();
        ether.srcAddr(SRC_MAC)
             .dstAddr(DST_MAC)
             .type(EtherType.IPV4)
             .paddingAtBuild(true)
             .payloadBuilder(ip);

        return ether.build();
    }

    private static Packet buildUdpPacket(String srcIp, String dstIp, int srcPort, int dstPort, byte[] payload) throws Exception {
        Inet4Address srcInet = (Inet4Address) InetAddress.getByName(srcIp);
        Inet4Address dstInet = (Inet4Address) InetAddress.getByName(dstIp);

        UdpPacket.Builder udp = new UdpPacket.Builder();
        udp.srcPort(UdpPort.getInstance((short) srcPort))
           .dstPort(UdpPort.getInstance((short) dstPort))
           .srcAddr(srcInet)
           .dstAddr(dstInet)
           .correctChecksumAtBuild(true)
           .correctLengthAtBuild(true)
           .payloadBuilder(new UnknownPacket.Builder().rawData(payload));

        IpV4Packet.Builder ip = new IpV4Packet.Builder();
        ip.version(IpVersion.IPV4)
          .tos(IpV4Rfc791Tos.newInstance((byte) 0))
          .ttl((byte) 64)
          .protocol(IpNumber.UDP)
          .srcAddr(srcInet)
          .dstAddr(dstInet)
          .correctChecksumAtBuild(true)
          .correctLengthAtBuild(true)
          .payloadBuilder(udp);

        EthernetPacket.Builder ether = new EthernetPacket.Builder();
        ether.srcAddr(SRC_MAC)
             .dstAddr(DST_MAC)
             .type(EtherType.IPV4)
             .paddingAtBuild(true)
             .payloadBuilder(ip);

        return ether.build();
    }

    private static byte[] createDnsQueryPayload(String domain) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[] { 0x12, 0x34 }); // ID
        out.write(new byte[] { 0x01, 0x00 }); // Flags
        out.write(new byte[] { 0x00, 0x01 }); // Questions: 1
        out.write(new byte[] { 0x00, 0x00 });
        out.write(new byte[] { 0x00, 0x00 });
        out.write(new byte[] { 0x00, 0x00 });

        for (String label : domain.split("\\.")) {
            out.write((byte) label.length());
            out.write(label.getBytes(StandardCharsets.US_ASCII));
        }
        out.write((byte) 0); // Terminating 0
        out.write(new byte[] { 0x00, 0x01 }); // QTYPE: A
        out.write(new byte[] { 0x00, 0x01 }); // QCLASS: IN
        return out.toByteArray();
    }

    private static byte[] createTlsClientHelloPayload(String sniHostname) throws IOException {
        ByteArrayOutputStream handshakeBody = new ByteArrayOutputStream();
        handshakeBody.write(new byte[] { 0x03, 0x03 }); // TLS 1.2
        handshakeBody.write(new byte[32]); // Random
        handshakeBody.write((byte) 0); // Session ID
        handshakeBody.write(new byte[] { 0x00, 0x02 }); // Cipher Suites Len
        handshakeBody.write(new byte[] { (byte) 0xc0, 0x2f });
        handshakeBody.write((byte) 1); // Compression Len
        handshakeBody.write((byte) 0);

        // SNI Extension
        byte[] nameBytes = sniHostname.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream sniData = new ByteArrayOutputStream();
        int listLen = 3 + nameBytes.length;
        sniData.write((byte) ((listLen >> 8) & 0xFF));
        sniData.write((byte) (listLen & 0xFF));
        sniData.write((byte) 0); // Host Name
        sniData.write((byte) ((nameBytes.length >> 8) & 0xFF));
        sniData.write((byte) (nameBytes.length & 0xFF));
        sniData.write(nameBytes);

        byte[] sniPayload = sniData.toByteArray();
        ByteArrayOutputStream extStream = new ByteArrayOutputStream();
        extStream.write(new byte[] { 0x00, 0x00 }); // Type SNI
        extStream.write((byte) ((sniPayload.length >> 8) & 0xFF));
        extStream.write((byte) (sniPayload.length & 0xFF));
        extStream.write(sniPayload);

        byte[] allExt = extStream.toByteArray();
        handshakeBody.write((byte) ((allExt.length >> 8) & 0xFF));
        handshakeBody.write((byte) (allExt.length & 0xFF));
        handshakeBody.write(allExt);

        byte[] hsData = handshakeBody.toByteArray();

        ByteArrayOutputStream recordStream = new ByteArrayOutputStream();
        recordStream.write((byte) 0x16); // Handshake
        recordStream.write(new byte[] { 0x03, 0x01 }); // TLS 1.0
        int recordLen = 4 + hsData.length;
        recordStream.write((byte) ((recordLen >> 8) & 0xFF));
        recordStream.write((byte) (recordLen & 0xFF));
        recordStream.write((byte) 0x01); // Client Hello
        recordStream.write((byte) ((hsData.length >> 16) & 0xFF));
        recordStream.write((byte) ((hsData.length >> 8) & 0xFF));
        recordStream.write((byte) (hsData.length & 0xFF));
        recordStream.write(hsData);

        return recordStream.toByteArray();
    }
}
