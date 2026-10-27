package com.dpi.statistics;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

/**
 * Thread-safe statistics engine using LongAdder for high-performance counting.
 */
public class StatsEngine {
    private final LongAdder totalPackets = new LongAdder();
    private final LongAdder totalBytes = new LongAdder();

    private final LongAdder tcpPackets = new LongAdder();
    private final LongAdder udpPackets = new LongAdder();
    private final LongAdder icmpPackets = new LongAdder();
    private final LongAdder ipv4Packets = new LongAdder();
    private final LongAdder ipv6Packets = new LongAdder();
    private final LongAdder otherPackets = new LongAdder();

    private final LongAdder blockedPackets = new LongAdder();
    private final LongAdder allowedPackets = new LongAdder();
    private final LongAdder threatCount = new LongAdder();

    private final LongAdder activeFlows = new LongAdder();
    private final LongAdder completedFlows = new LongAdder();

    // Application protocol counters
    private final ConcurrentHashMap<String, LongAdder> appProtocolCounts = new ConcurrentHashMap<>();

    private volatile long startTimeMillis = System.currentTimeMillis();

    public void recordPacket(String protocol, int length) {
        totalPackets.increment();
        totalBytes.add(length);

        switch (protocol) {
            case "TCP" -> tcpPackets.increment();
            case "UDP" -> udpPackets.increment();
            case "ICMP" -> icmpPackets.increment();
            case "ICMPv6" -> icmpPackets.increment();
            case "IPv4" -> ipv4Packets.increment();
            case "IPv6" -> ipv6Packets.increment();
            default -> otherPackets.increment();
        }
    }

    public void recordAppProtocol(String appProtocol) {
        appProtocolCounts.computeIfAbsent(appProtocol, k -> new LongAdder()).increment();
    }

    public void recordBlocked() { blockedPackets.increment(); }
    public void recordAllowed() { allowedPackets.increment(); }
    public void recordThreat() { threatCount.increment(); }
    public void recordFlowCreated() { activeFlows.increment(); }
    public void recordFlowExpired() { activeFlows.decrement(); completedFlows.increment(); }

    public long getTotalPackets() { return totalPackets.sum(); }
    public long getTotalBytes() { return totalBytes.sum(); }
    public long getTcpPackets() { return tcpPackets.sum(); }
    public long getUdpPackets() { return udpPackets.sum(); }
    public long getIcmpPackets() { return icmpPackets.sum(); }
    public long getBlockedPackets() { return blockedPackets.sum(); }
    public long getAllowedPackets() { return allowedPackets.sum(); }
    public long getThreatCount() { return threatCount.sum(); }
    public long getActiveFlows() { return activeFlows.sum(); }
    public long getCompletedFlows() { return completedFlows.sum(); }

    public double getPacketsPerSec() {
        long elapsed = System.currentTimeMillis() - startTimeMillis;
        return elapsed > 0 ? (totalPackets.sum() * 1000.0) / elapsed : 0;
    }

    public double getBytesPerSec() {
        long elapsed = System.currentTimeMillis() - startTimeMillis;
        return elapsed > 0 ? (totalBytes.sum() * 1000.0) / elapsed : 0;
    }

    public Map<String, LongAdder> getAppProtocolCounts() {
        return appProtocolCounts;
    }

    public void resetStartTime() {
        startTimeMillis = System.currentTimeMillis();
    }

    /**
     * Returns a formatted human-readable byte count string.
     */
    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        else if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        else if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        else return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }
}
