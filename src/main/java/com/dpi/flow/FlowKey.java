package com.dpi.flow;

import java.util.Objects;

/**
 * Represents a normalized 5-tuple used to identify a bidirectional flow.
 * Ensures that A->B and B->A hash to the exact same key.
 */
public class FlowKey {
    private final String ip1;
    private final String ip2;
    private final int port1;
    private final int port2;
    private final String protocol;

    public FlowKey(String srcIp, String dstIp, int srcPort, int dstPort, String protocol) {
        this.protocol = protocol;
        
        // Normalize direction: always put the lexicographically smaller IP first.
        // If IPs are the same, order by port.
        int ipCompare = srcIp.compareTo(dstIp);
        if (ipCompare < 0) {
            this.ip1 = srcIp;
            this.ip2 = dstIp;
            this.port1 = srcPort;
            this.port2 = dstPort;
        } else if (ipCompare > 0) {
            this.ip1 = dstIp;
            this.ip2 = srcIp;
            this.port1 = dstPort;
            this.port2 = srcPort;
        } else {
            this.ip1 = srcIp;
            this.ip2 = dstIp;
            if (srcPort <= dstPort) {
                this.port1 = srcPort;
                this.port2 = dstPort;
            } else {
                this.port1 = dstPort;
                this.port2 = srcPort;
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FlowKey flowKey = (FlowKey) o;
        return port1 == flowKey.port1 &&
               port2 == flowKey.port2 &&
               ip1.equals(flowKey.ip1) &&
               ip2.equals(flowKey.ip2) &&
               protocol.equals(flowKey.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ip1, ip2, port1, port2, protocol);
    }

    @Override
    public String toString() {
        return protocol + ":" + ip1 + ":" + port1 + "<->" + ip2 + ":" + port2;
    }
}
