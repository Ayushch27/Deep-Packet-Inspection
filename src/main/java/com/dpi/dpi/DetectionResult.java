package com.dpi.dpi;

/**
 * Represents the outcome of a protocol detection attempt.
 */
public class DetectionResult {
    private final String protocol;
    private final double confidence;
    private final String detectionMethod;

    public DetectionResult(String protocol, double confidence, String detectionMethod) {
        this.protocol = protocol;
        this.confidence = confidence;
        this.detectionMethod = detectionMethod;
    }

    public String getProtocol() {
        return protocol;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getDetectionMethod() {
        return detectionMethod;
    }
}
