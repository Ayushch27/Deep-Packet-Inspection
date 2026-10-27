package com.dpi.cli;

import com.dpi.detection.ThreatResult;
import com.dpi.statistics.StatsEngine;

import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.LongAdder;

/**
 * Renders a professional CLI dashboard summarizing DPI engine state.
 */
public class Dashboard {
    private final StatsEngine stats;
    private final String mode;
    private final String inputSource;
    private final int workers;

    // Keep the last 5 alerts for display
    private final Deque<ThreatResult> recentAlerts = new ConcurrentLinkedDeque<>();
    private static final int MAX_RECENT_ALERTS = 5;

    public Dashboard(StatsEngine stats, String mode, String inputSource, int workers) {
        this.stats = stats;
        this.mode = mode;
        this.inputSource = inputSource;
        this.workers = workers;
    }

    public void addAlert(ThreatResult threat) {
        recentAlerts.addLast(threat);
        while (recentAlerts.size() > MAX_RECENT_ALERTS) {
            recentAlerts.pollFirst();
        }
    }

    /**
     * Renders and returns the full dashboard string.
     */
    public String render() {
        StringBuilder sb = new StringBuilder();
        String sep = "--------------------------------------------------------";

        sb.append("========================================================\n");
        sb.append("        JAVA DEEP PACKET INSPECTION ENGINE\n");
        sb.append("========================================================\n\n");

        sb.append(String.format("Mode        : %s%n", mode));
        sb.append(String.format("Input       : %s%n", inputSource));
        sb.append(String.format("Workers     : %d%n", workers));
        sb.append(String.format("Status      : RUNNING%n%n"));

        sb.append(sep).append("\nTRAFFIC STATISTICS\n").append(sep).append("\n\n");
        sb.append(String.format("Packets        : %,d%n", stats.getTotalPackets()));
        sb.append(String.format("Bytes          : %s%n", StatsEngine.formatBytes(stats.getTotalBytes())));
        sb.append(String.format("Packets/sec    : %,.0f%n", stats.getPacketsPerSec()));
        sb.append(String.format("Bytes/sec      : %s/s%n%n", StatsEngine.formatBytes((long) stats.getBytesPerSec())));
        sb.append(String.format("TCP            : %,d%n", stats.getTcpPackets()));
        sb.append(String.format("UDP            : %,d%n", stats.getUdpPackets()));
        sb.append(String.format("ICMP           : %,d%n%n", stats.getIcmpPackets()));

        sb.append(sep).append("\nFLOWS\n").append(sep).append("\n\n");
        sb.append(String.format("Active         : %,d%n", stats.getActiveFlows()));
        sb.append(String.format("Completed      : %,d%n%n", stats.getCompletedFlows()));

        sb.append(sep).append("\nAPPLICATIONS\n").append(sep).append("\n\n");
        Map<String, LongAdder> appCounts = stats.getAppProtocolCounts();
        long totalAppPackets = appCounts.values().stream().mapToLong(LongAdder::sum).sum();
        if (totalAppPackets > 0) {
            appCounts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue().sum(), a.getValue().sum()))
                .limit(10)
                .forEach(e -> {
                    double pct = (e.getValue().sum() * 100.0) / totalAppPackets;
                    sb.append(String.format("%-15s: %5.1f%%%n", e.getKey(), pct));
                });
        } else {
            sb.append("No application data yet.\n");
        }
        sb.append("\n");

        sb.append(sep).append("\nSECURITY\n").append(sep).append("\n\n");
        sb.append(String.format("Threats        : %,d%n", stats.getThreatCount()));
        sb.append(String.format("Blocked        : %,d%n", stats.getBlockedPackets()));
        sb.append(String.format("Allowed        : %,d%n%n", stats.getAllowedPackets()));

        if (!recentAlerts.isEmpty()) {
            sb.append(sep).append("\nRECENT ALERTS\n").append(sep).append("\n\n");
            for (ThreatResult alert : recentAlerts) {
                sb.append(String.format("[%s] %s%n", alert.getSeverity(), alert.getType()));
                sb.append(String.format("  Source      : %s%n", alert.getSourceIp()));
                sb.append(String.format("  Dest        : %s%n", alert.getDestinationIp()));
                sb.append(String.format("  Evidence    : %s%n", alert.getEvidence()));
                sb.append(String.format("  Confidence  : %.2f%n%n", alert.getConfidence()));
            }
        }

        sb.append("========================================================\n");
        return sb.toString();
    }
}
