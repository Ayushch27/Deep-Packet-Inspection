package com.dpi.detection;

import com.dpi.model.PacketInfo;
import com.dpi.flow.Flow;
import java.util.Optional;

public interface ThreatDetector {
    /**
     * Analyzes a packet within the context of its flow to detect malicious behavior.
     * 
     * @param packet The latest packet
     * @param flow The associated bidirectional flow, can be null if stateless traffic
     * @return Optional containing a ThreatResult if a threat is detected
     */
    Optional<ThreatResult> analyze(PacketInfo packet, Flow flow);
}
