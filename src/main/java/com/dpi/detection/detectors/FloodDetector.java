package com.dpi.detection.detectors;

import com.dpi.detection.ThreatDetector;
import com.dpi.detection.ThreatResult;
import com.dpi.detection.ThreatSeverity;
import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Generic volumetric flood detector (SYN Flood, ICMP Flood, UDP Flood).
 */
public class FloodDetector implements ThreatDetector {
    private final String protocol;
    private final boolean onlySyn;
    private final int threshold;
    private final long windowMillis;
    private final String threatName;
    private final ThreatSeverity severity;
    
    // Source IP -> Flood State
    private final Map<String, FloodState> stateMap = new ConcurrentHashMap<>();

    public FloodDetector(String protocol, boolean onlySyn, int threshold, long windowSeconds, String threatName, ThreatSeverity severity) {
        this.protocol = protocol;
        this.onlySyn = onlySyn;
        this.threshold = threshold;
        this.windowMillis = windowSeconds * 1000;
        this.threatName = threatName;
        this.severity = severity;
    }

    @Override
    public Optional<ThreatResult> analyze(PacketInfo packet, Flow flow) {
        if (!protocol.equals(packet.getProtocol())) {
            return Optional.empty();
        }
        
        // For TCP SYN floods, verify the SYN flag is set and ACK is NOT set
        if (onlySyn) {
            // TCP Flags: 0x02 is SYN, 0x10 is ACK
            boolean isSyn = (packet.getTcpFlags() & 0x02) != 0;
            boolean isAck = (packet.getTcpFlags() & 0x10) != 0;
            if (!isSyn || isAck) {
                return Optional.empty();
            }
        }

        String srcIp = packet.getSrcIp();
        long now = packet.getTimestamp();

        FloodState state = stateMap.computeIfAbsent(srcIp, k -> new FloodState(now));

        synchronized (state) {
            if (now - state.startTime > windowMillis) {
                state.reset(now);
            }
            
            state.count++;
            
            if (!state.alerted && state.count >= threshold) {
                state.alerted = true;
                ThreatResult result = new ThreatResult(
                    threatName,
                    severity,
                    srcIp,
                    packet.getDstIp(), // If distributed, this is just one of the targets
                    String.format("Sent %d %s packets within %d ms", state.count, (onlySyn ? "SYN" : protocol), (now - state.startTime)),
                    0.90,
                    now
                );
                return Optional.of(result);
            }
        }

        return Optional.empty();
    }

    private static class FloodState {
        long startTime;
        int count = 0;
        boolean alerted = false;

        FloodState(long startTime) {
            this.startTime = startTime;
        }

        void reset(long startTime) {
            this.startTime = startTime;
            this.count = 0;
            this.alerted = false;
        }
    }
}
