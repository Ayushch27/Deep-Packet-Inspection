package com.dpi.detection;

import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Manages security detectors and aggregates risk scores per source IP.
 */
public class ThreatDetectionEngine {
    private final List<ThreatDetector> detectors = new ArrayList<>();
    
    // Tracks accumulated risk score (0 - 100) per Source IP
    private final Map<String, Double> riskScores = new ConcurrentHashMap<>();
    
    // Callback to handle newly detected threats (e.g. logging or alerting)
    private final Consumer<ThreatResult> alertHandler;

    public ThreatDetectionEngine(Consumer<ThreatResult> alertHandler) {
        this.alertHandler = alertHandler;
    }

    public void addDetector(ThreatDetector detector) {
        detectors.add(detector);
    }

    /**
     * Analyzes the packet against all registered threat detectors.
     */
    public void analyze(PacketInfo packet, Flow flow) {
        for (ThreatDetector detector : detectors) {
            detector.analyze(packet, flow).ifPresent(threat -> {
                
                // Determine risk impact based on severity
                double additionalRisk = switch (threat.getSeverity()) {
                    case CRITICAL -> 50.0;
                    case HIGH -> 40.0;
                    case MEDIUM -> 25.0;
                    case LOW -> 10.0;
                };

                // Accumulate risk for the source IP, capped at 100
                riskScores.compute(threat.getSourceIp(), (ip, oldScore) -> {
                    double newScore = (oldScore == null ? 0 : oldScore) + additionalRisk;
                    return Math.min(100.0, newScore);
                });

                // Attach risk score to the flow as well
                if (flow != null) {
                    flow.addRiskScore(additionalRisk);
                }

                // Fire alert
                if (alertHandler != null) {
                    alertHandler.accept(threat);
                }
            });
        }
    }

    public double getRiskScore(String sourceIp) {
        return riskScores.getOrDefault(sourceIp, 0.0);
    }
}
