package com.dpi.flow;

import com.dpi.model.PacketInfo;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents an active network flow, tracking bidirectional statistics, application data, and threats.
 */
public class Flow {
    private final FlowKey flowKey;
    private final String sourceIp;      // The IP that initiated the flow
    private final String destinationIp;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol;

    private final long startTime;
    private volatile long lastSeenTime;

    // Traffic counters
    private final AtomicLong packetsForward = new AtomicLong(0);
    private final AtomicLong packetsReverse = new AtomicLong(0);
    private final AtomicLong bytesForward = new AtomicLong(0);
    private final AtomicLong bytesReverse = new AtomicLong(0);

    // DPI & Security placeholders (populated in future milestones)
    private volatile String applicationProtocol = "Unknown";
    private volatile double confidence = 0.0;
    
    // Extracted Metadata
    private volatile com.dpi.model.HttpMetadata httpMetadata;
    private volatile com.dpi.model.TlsMetadata tlsMetadata;
    private volatile com.dpi.model.DnsMetadata dnsMetadata;

    private volatile double riskScore = 0.0;
    private volatile boolean blockAlerted = false;

    public Flow(PacketInfo packet, FlowKey flowKey) {
        this.flowKey = flowKey;
        this.sourceIp = packet.getSrcIp();
        this.destinationIp = packet.getDstIp();
        this.sourcePort = packet.getSrcPort() != null ? packet.getSrcPort() : 0;
        this.destinationPort = packet.getDstPort() != null ? packet.getDstPort() : 0;
        this.protocol = packet.getProtocol();
        this.startTime = packet.getTimestamp();
        this.lastSeenTime = packet.getTimestamp();
        
        addPacket(packet);
    }

    public Flow(String flowId, String sourceIp, String destinationIp, int sourcePort, int destinationPort, String protocol, long timestamp) {
        this.flowKey = new FlowKey(sourceIp, destinationIp, sourcePort, destinationPort, protocol);
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.startTime = timestamp;
        this.lastSeenTime = timestamp;
    }

    /**
     * Updates the flow state with a newly observed packet.
     * @param packet The parsed packet info.
     */
    public void addPacket(PacketInfo packet) {
        this.lastSeenTime = Math.max(this.lastSeenTime, packet.getTimestamp());
        
        // Determine direction relative to the initiator
        boolean isForward = packet.getSrcIp().equals(this.sourceIp) && 
                            (packet.getSrcPort() == null || packet.getSrcPort() == this.sourcePort);

        if (isForward) {
            packetsForward.incrementAndGet();
            bytesForward.addAndGet(packet.getPacketLength());
        } else {
            packetsReverse.incrementAndGet();
            bytesReverse.addAndGet(packet.getPacketLength());
        }
    }

    // Identifiers
    public FlowKey getFlowKey() { return flowKey; }
    public String getFlowId() { return flowKey.toString(); }
    public String getSourceIp() { return sourceIp; }
    public String getDestinationIp() { return destinationIp; }
    public int getSourcePort() { return sourcePort; }
    public int getDestinationPort() { return destinationPort; }
    public String getProtocol() { return protocol; }

    // Timing
    public long getStartTime() { return startTime; }
    public long getLastSeenTime() { return lastSeenTime; }
    public long getDuration() { return lastSeenTime - startTime; }

    // Traffic Stats
    public long getPacketsForward() { return packetsForward.get(); }
    public long getPacketsReverse() { return packetsReverse.get(); }
    public long getTotalPackets() { return packetsForward.get() + packetsReverse.get(); }
    public long getBytesForward() { return bytesForward.get(); }
    public long getBytesReverse() { return bytesReverse.get(); }
    public long getTotalBytes() { return bytesForward.get() + bytesReverse.get(); }

    // Application & Security Data
    public String getApplicationProtocol() { return applicationProtocol; }
    public void setApplicationProtocol(String applicationProtocol, double confidence) { 
        this.applicationProtocol = applicationProtocol; 
        this.confidence = confidence;
    }
    public double getConfidence() { return confidence; }
    
    public com.dpi.model.HttpMetadata getHttpMetadata() { return httpMetadata; }
    public void setHttpMetadata(com.dpi.model.HttpMetadata httpMetadata) { this.httpMetadata = httpMetadata; }
    
    public com.dpi.model.TlsMetadata getTlsMetadata() { return tlsMetadata; }
    public void setTlsMetadata(com.dpi.model.TlsMetadata tlsMetadata) { this.tlsMetadata = tlsMetadata; }
    
    public com.dpi.model.DnsMetadata getDnsMetadata() { return dnsMetadata; }
    public void setDnsMetadata(com.dpi.model.DnsMetadata dnsMetadata) { this.dnsMetadata = dnsMetadata; }
    
    public double getRiskScore() { return riskScore; }
    public void addRiskScore(double additionalRisk) {
        this.riskScore = Math.min(100.0, this.riskScore + additionalRisk);
    }
    
    public boolean isBlockAlerted() { return blockAlerted; }
    public void setBlockAlerted(boolean blockAlerted) { this.blockAlerted = blockAlerted; }
}
