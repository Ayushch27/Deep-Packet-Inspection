package com.dpi.dpi;

import com.dpi.dpi.detectors.BasicPayloadDetector;
import com.dpi.dpi.detectors.DnsDetector;
import com.dpi.dpi.detectors.HttpDetector;
import com.dpi.dpi.detectors.PortBasedDetector;
import com.dpi.dpi.detectors.TlsDetector;
import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;

import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrates Protocol Detectors to classify network flows.
 */
public class DPIEngine {
    private final List<ProtocolDetector> detectors = new ArrayList<>();

    public DPIEngine() {
        // Register advanced detectors first
        detectors.add(new HttpDetector());
        detectors.add(new TlsDetector());
        detectors.add(new DnsDetector());
        
        // Register basic / fallback detectors
        detectors.add(new BasicPayloadDetector()); 
        detectors.add(new PortBasedDetector());
    }

    /**
     * Analyzes a packet within the context of its flow to classify the application protocol.
     * 
     * @param flow The flow tracking state.
     * @param packet The latest packet to analyze.
     */
    public void analyze(Flow flow, PacketInfo packet) {
        // If we already have a very high confidence classification (>90%), skip further DPI
        if (flow.getConfidence() >= 0.9) {
            return;
        }

        DetectionResult bestResult = null;

        for (ProtocolDetector detector : detectors) {
            DetectionResult result = detector.detect(flow, packet);
            if (result != null) {
                if (bestResult == null || result.getConfidence() > bestResult.getConfidence()) {
                    bestResult = result;
                }
            }
        }

        if (bestResult != null) {
            // Only update if it improves confidence
            if (bestResult.getConfidence() > flow.getConfidence()) {
                flow.setApplicationProtocol(bestResult.getProtocol(), bestResult.getConfidence());
            }
        } else if ("Unknown".equals(flow.getApplicationProtocol())) {
            // Fallback: If everything fails, at least label it by its L4 transport protocol
            flow.setApplicationProtocol(flow.getProtocol(), 0.1); 
        }
    }
}
