package com.dpi.flow;

import com.dpi.model.PacketInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

public class FlowTrackerTest {

    private FlowTracker tracker;
    private AtomicInteger expiredCount;
    private AtomicReference<Flow> lastExpiredFlow;

    @BeforeEach
    public void setUp() {
        expiredCount = new AtomicInteger(0);
        lastExpiredFlow = new AtomicReference<>();
        tracker = new FlowTracker(10, expiredFlow -> {
            expiredCount.incrementAndGet();
            lastExpiredFlow.set(expiredFlow);
        });
    }

    @Test
    public void testBidirectionalFlowTracking() {
        PacketInfo fwdPacket = new PacketInfo.Builder()
                .timestamp(1000L)
                .srcIp("192.168.1.10")
                .dstIp("10.0.0.1")
                .srcPort(12345)
                .dstPort(80)
                .protocol("TCP")
                .packetLength(100)
                .payloadLength(50)
                .build();

        PacketInfo revPacket = new PacketInfo.Builder()
                .timestamp(1050L)
                .srcIp("10.0.0.1")
                .dstIp("192.168.1.10")
                .srcPort(80)
                .dstPort(12345)
                .protocol("TCP")
                .packetLength(200)
                .payloadLength(150)
                .build();

        Flow fwdFlow = tracker.processPacket(fwdPacket);
        assertNotNull(fwdFlow);
        assertEquals(1, fwdFlow.getTotalPackets());
        assertEquals(1, fwdFlow.getPacketsForward());
        assertEquals(0, fwdFlow.getPacketsReverse());
        assertEquals(100, fwdFlow.getBytesForward());
        assertEquals(0, fwdFlow.getBytesReverse());

        Flow revFlow = tracker.processPacket(revPacket);
        assertSame(fwdFlow, revFlow);
        assertEquals(2, revFlow.getTotalPackets());
        assertEquals(1, revFlow.getPacketsForward());
        assertEquals(1, revFlow.getPacketsReverse());
        assertEquals(100, revFlow.getBytesForward());
        assertEquals(200, revFlow.getBytesReverse());
    }

    @Test
    public void testFlowExpiration() {
        PacketInfo packet = new PacketInfo.Builder()
                .timestamp(1000L)
                .srcIp("192.168.1.10")
                .dstIp("10.0.0.1")
                .srcPort(12345)
                .dstPort(80)
                .protocol("TCP")
                .packetLength(100)
                .payloadLength(50)
                .build();

        tracker.processPacket(packet);
        assertEquals(1, tracker.getActiveFlowCount());

        // Fast forward time past timeout (timeout is 10 seconds = 10,000 ms)
        tracker.cleanupStaleFlows(1000L + 15_000L);

        assertEquals(0, tracker.getActiveFlowCount());
        assertEquals(1, expiredCount.get());
        assertNotNull(lastExpiredFlow.get());
        assertEquals("192.168.1.10", lastExpiredFlow.get().getSourceIp());
    }

    @Test
    public void testFlowKeySymmetry() {
        FlowKey key1 = new FlowKey("192.168.1.10", "10.0.0.1", 12345, 80, "TCP");
        FlowKey key2 = new FlowKey("10.0.0.1", "192.168.1.10", 80, 12345, "TCP");

        assertEquals(key1, key2);
        assertEquals(key1.hashCode(), key2.hashCode());
    }
}
