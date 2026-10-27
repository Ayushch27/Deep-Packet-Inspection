package com.dpi.detection;

public class ThreatResult {
    private final String type;
    private final ThreatSeverity severity;
    private final String sourceIp;
    private final String destinationIp;
    private final String evidence;
    private final double confidence;
    private final long timestamp;

    public ThreatResult(String type, ThreatSeverity severity, String sourceIp, String destinationIp, String evidence, double confidence, long timestamp) {
        this.type = type;
        this.severity = severity;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.evidence = evidence;
        this.confidence = confidence;
        this.timestamp = timestamp;
    }

    public String getType() { return type; }
    public ThreatSeverity getSeverity() { return severity; }
    public String getSourceIp() { return sourceIp; }
    public String getDestinationIp() { return destinationIp; }
    public String getEvidence() { return evidence; }
    public double getConfidence() { return confidence; }
    public long getTimestamp() { return timestamp; }

    @Override
    public String toString() {
        return String.format("[%s] %s from %s to %s (Evidence: %s)", severity.name(), type, sourceIp, destinationIp, evidence);
    }
}
