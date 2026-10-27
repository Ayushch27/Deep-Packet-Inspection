package com.dpi.detection;

import com.dpi.detection.detectors.FloodDetector;
import com.dpi.detection.detectors.PortScanDetector;
import com.dpi.model.PacketInfo;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ThreatDetectionEngineTest {

    @Test
    public void testPortScanDetection() {
        List<ThreatResult> alerts = new ArrayList<>();
        ThreatDetectionEngine engine = new ThreatDetectionEngine(alerts::add);
        // Threshold: 10 ports, Window: 5 seconds
        engine.addDetector(new PortScanDetector(10, 5));

        long startTime = 1_000_000L;
        String attackerIp = "192.168.1.99";

        // Hit 9 distinct ports (under threshold)
        for (int port = 1; port <= 9; port++) {
            PacketInfo packet = new PacketInfo.Builder()
                    .timestamp(startTime + (port * 100))
                    .srcIp(attackerIp)
                    .dstIp("10.0.0.1")
                    .srcPort(40000 + port)
                    .dstPort(port)
                    .protocol("TCP")
                    .tcpFlags(0x02) // SYN
                    .build();
            engine.analyze(packet, null);
        }
        assertEquals(0, alerts.size());

        // Hit 10th port -> triggers alert!
        PacketInfo triggerPacket = new PacketInfo.Builder()
                .timestamp(startTime + 1000)
                .srcIp(attackerIp)
                .dstIp("10.0.0.1")
                .srcPort(40010)
                .dstPort(10)
                .protocol("TCP")
                .tcpFlags(0x02)
                .build();
        engine.analyze(triggerPacket, null);

        assertEquals(1, alerts.size());
        ThreatResult alert = alerts.get(0);
        assertEquals("Port Scan", alert.getType());
        assertEquals(ThreatSeverity.HIGH, alert.getSeverity());
        assertEquals(attackerIp, alert.getSourceIp());

        // Hit 11th port -> should not duplicate alert within same window
        PacketInfo eleventhPacket = new PacketInfo.Builder()
                .timestamp(startTime + 1100)
                .srcIp(attackerIp)
                .dstIp("10.0.0.1")
                .srcPort(40011)
                .dstPort(11)
                .protocol("TCP")
                .tcpFlags(0x02)
                .build();
        engine.analyze(eleventhPacket, null);
        assertEquals(1, alerts.size());
    }

    @Test
    public void testSynFloodDetection() {
        List<ThreatResult> alerts = new ArrayList<>();
        ThreatDetectionEngine engine = new ThreatDetectionEngine(alerts::add);
        // Threshold: 50 SYN packets, Window: 2 seconds
        engine.addDetector(new FloodDetector("TCP", true, 50, 2, "SYN Flood", ThreatSeverity.HIGH));

        long baseTime = 1_000_000L;
        String attacker = "172.16.0.50";

        // Send 49 SYN packets
        for (int i = 0; i < 49; i++) {
            PacketInfo syn = new PacketInfo.Builder()
                    .timestamp(baseTime + (i * 10))
                    .srcIp(attacker)
                    .dstIp("10.0.0.1")
                    .srcPort(30000 + i)
                    .dstPort(80)
                    .protocol("TCP")
                    .tcpFlags(0x02) // SYN only
                    .build();
            engine.analyze(syn, null);
        }
        assertEquals(0, alerts.size());

        // 50th SYN packet -> triggers alert!
        PacketInfo trigger = new PacketInfo.Builder()
                .timestamp(baseTime + 500)
                .srcIp(attacker)
                .dstIp("10.0.0.1")
                .srcPort(30050)
                .dstPort(80)
                .protocol("TCP")
                .tcpFlags(0x02)
                .build();
        engine.analyze(trigger, null);

        assertEquals(1, alerts.size());
        assertEquals("SYN Flood", alerts.get(0).getType());
        assertEquals(ThreatSeverity.HIGH, alerts.get(0).getSeverity());
    }

    @Test
    public void testAckPacketsDoNotTriggerSynFlood() {
        List<ThreatResult> alerts = new ArrayList<>();
        ThreatDetectionEngine engine = new ThreatDetectionEngine(alerts::add);
        engine.addDetector(new FloodDetector("TCP", true, 20, 2, "SYN Flood", ThreatSeverity.HIGH));

        long baseTime = 1_000_000L;
        String sender = "172.16.0.50";

        // Send 30 ACK packets (0x10) or SYN-ACK packets (0x12)
        for (int i = 0; i < 30; i++) {
            PacketInfo ack = new PacketInfo.Builder()
                    .timestamp(baseTime + (i * 10))
                    .srcIp(sender)
                    .dstIp("10.0.0.1")
                    .srcPort(30000 + i)
                    .dstPort(80)
                    .protocol("TCP")
                    .tcpFlags(0x10) // ACK only
                    .build();
            engine.analyze(ack, null);
        }

        assertEquals(0, alerts.size(), "ACK packets must not trigger SYN Flood detector");
    }
}
