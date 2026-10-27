package com.dpi.rules;

import com.dpi.flow.Flow;
import com.dpi.model.DnsMetadata;
import com.dpi.model.HttpMetadata;
import com.dpi.model.PacketInfo;
import com.dpi.model.TlsMetadata;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class RuleEngineTest {

    @TempDir
    Path tempDir;

    @Test
    public void testIpBlockRule() throws IOException {
        Path rulesFile = tempDir.resolve("rules.json");
        String json = """
                {
                  "block_ips": ["192.168.1.100", "10.0.0.5"],
                  "allow_ips": [],
                  "block_domains": [],
                  "allow_domains": []
                }
                """;
        Files.writeString(rulesFile, json);

        RuleEngine engine = new RuleEngine(rulesFile.toString());

        PacketInfo blockedSrc = new PacketInfo.Builder()
                .srcIp("192.168.1.100")
                .dstIp("8.8.8.8")
                .protocol("TCP")
                .build();
        assertEquals(RuleAction.BLOCK, engine.evaluate(blockedSrc, null));

        PacketInfo blockedDst = new PacketInfo.Builder()
                .srcIp("192.168.1.50")
                .dstIp("10.0.0.5")
                .protocol("TCP")
                .build();
        assertEquals(RuleAction.BLOCK, engine.evaluate(blockedDst, null));

        PacketInfo allowedPacket = new PacketInfo.Builder()
                .srcIp("192.168.1.50")
                .dstIp("8.8.8.8")
                .protocol("TCP")
                .build();
        assertEquals(RuleAction.ALLOW, engine.evaluate(allowedPacket, null));
    }

    @Test
    public void testDomainBlockRuleAcrossProtocols() throws IOException {
        Path rulesFile = tempDir.resolve("rules.json");
        String json = """
                {
                  "block_ips": [],
                  "allow_ips": [],
                  "block_domains": ["malicious.org", "badsite.com"],
                  "allow_domains": []
                }
                """;
        Files.writeString(rulesFile, json);

        RuleEngine engine = new RuleEngine(rulesFile.toString());

        PacketInfo packet = new PacketInfo.Builder()
                .srcIp("192.168.1.50")
                .dstIp("93.184.216.34")
                .protocol("TCP")
                .build();

        // 1. HTTP Host blocking
        Flow httpFlow = new Flow("flow-1", "192.168.1.50", "93.184.216.34", 50000, 80, "TCP", 1000L);
        HttpMetadata httpMeta = new HttpMetadata();
        httpMeta.setHost("sub.malicious.org");
        httpFlow.setHttpMetadata(httpMeta);
        assertEquals(RuleAction.BLOCK, engine.evaluate(packet, httpFlow));

        // 2. TLS SNI blocking
        Flow tlsFlow = new Flow("flow-2", "192.168.1.50", "93.184.216.34", 50001, 443, "TCP", 1000L);
        TlsMetadata tlsMeta = new TlsMetadata();
        tlsMeta.setSni("badsite.com");
        tlsFlow.setTlsMetadata(tlsMeta);
        assertEquals(RuleAction.BLOCK, engine.evaluate(packet, tlsFlow));

        // 3. DNS Query blocking
        Flow dnsFlow = new Flow("flow-3", "192.168.1.50", "8.8.8.8", 50002, 53, "UDP", 1000L);
        DnsMetadata dnsMeta = new DnsMetadata();
        dnsMeta.setQueryName("malicious.org");
        dnsFlow.setDnsMetadata(dnsMeta);
        assertEquals(RuleAction.BLOCK, engine.evaluate(packet, dnsFlow));

        // 4. Benign domain
        Flow benignFlow = new Flow("flow-4", "192.168.1.50", "1.1.1.1", 50003, 443, "TCP", 1000L);
        TlsMetadata benignMeta = new TlsMetadata();
        benignMeta.setSni("trusted.org");
        benignFlow.setTlsMetadata(benignMeta);
        assertEquals(RuleAction.ALLOW, engine.evaluate(packet, benignFlow));
    }

    @Test
    public void testCliPacketFilter() {
        PacketInfo tcpPacket = new PacketInfo.Builder()
                .protocol("TCP")
                .srcPort(54321)
                .dstPort(443)
                .srcIp("192.168.1.10")
                .dstIp("142.250.190.46")
                .build();

        Flow flow = new Flow("f-1", "192.168.1.10", "142.250.190.46", 54321, 443, "TCP", 1000L);
        flow.setApplicationProtocol("HTTPS/TLS", 0.95);

        PacketFilter protoFilter = new PacketFilter("protocol=TCP");
        assertTrue(protoFilter.matches(tcpPacket, flow));

        PacketFilter portFilter = new PacketFilter("port=443");
        assertTrue(portFilter.matches(tcpPacket, flow));

        PacketFilter portFilterMismatch = new PacketFilter("port=80");
        assertFalse(portFilterMismatch.matches(tcpPacket, flow));

        PacketFilter appFilter = new PacketFilter("app=HTTPS/TLS");
        assertTrue(appFilter.matches(tcpPacket, flow));

        PacketFilter srcFilter = new PacketFilter("src=192.168.1.10");
        assertTrue(srcFilter.matches(tcpPacket, flow));
    }
}
