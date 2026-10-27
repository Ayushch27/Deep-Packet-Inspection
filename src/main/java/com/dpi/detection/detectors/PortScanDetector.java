package com.dpi.detection.detectors;

import com.dpi.detection.ThreatDetector;
import com.dpi.detection.ThreatResult;
import com.dpi.detection.ThreatSeverity;
import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects if a single source IP contacts an unusually large number of destination ports
 * within a given time window.
 */
public class PortScanDetector implements ThreatDetector {
    private final int uniquePortsThreshold;
    private final long windowMillis;
    
    // Source IP -> Scanning State
    private final Map<String, ScanState> stateMap = new ConcurrentHashMap<>();

    public PortScanDetector(int uniquePortsThreshold, long windowSeconds) {
        this.uniquePortsThreshold = uniquePortsThreshold;
        this.windowMillis = windowSeconds * 1000;
    }

    @Override
    public Optional<ThreatResult> analyze(PacketInfo packet, Flow flow) {
        if (!"TCP".equals(packet.getProtocol()) && !"UDP".equals(packet.getProtocol())) {
            return Optional.empty(); // Port scans usually apply to TCP/UDP
        }
        if (packet.getDstPort() == null) {
            return Optional.empty();
        }

        String srcIp = packet.getSrcIp();
        long now = packet.getTimestamp();

        ScanState state = stateMap.computeIfAbsent(srcIp, k -> new ScanState(now));

        synchronized (state) {
            if (now - state.startTime > windowMillis) {
                state.reset(now);
            }
            
            state.ports.add(packet.getDstPort());
            
            if (!state.alerted && state.ports.size() >= uniquePortsThreshold) {
                state.alerted = true; // Prevent spamming alerts for the same window
                
                ThreatResult result = new ThreatResult(
                    "Port Scan",
                    ThreatSeverity.HIGH,
                    srcIp,
                    "Multiple Targets",
                    String.format("Hit %d unique ports within %d ms", state.ports.size(), (now - state.startTime)),
                    0.95,
                    now
                );
                return Optional.of(result);
            }
        }

        return Optional.empty();
    }

    private static class ScanState {
        long startTime;
        final Set<Integer> ports = new HashSet<>();
        boolean alerted = false;

        ScanState(long startTime) {
            this.startTime = startTime;
        }

        void reset(long startTime) {
            this.startTime = startTime;
            this.ports.clear();
            this.alerted = false;
        }
    }
}
