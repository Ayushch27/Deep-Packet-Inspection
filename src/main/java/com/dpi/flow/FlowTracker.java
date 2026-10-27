package com.dpi.flow;

import com.dpi.model.PacketInfo;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Tracks active bidirectional network flows, storing state and expiring old connections.
 */
public class FlowTracker {
    private final ConcurrentHashMap<FlowKey, Flow> activeFlows = new ConcurrentHashMap<>();
    private final long flowTimeoutMillis;
    private final Consumer<Flow> onFlowExpired;

    public FlowTracker(long flowTimeoutSeconds, Consumer<Flow> onFlowExpired) {
        this.flowTimeoutMillis = flowTimeoutSeconds * 1000;
        this.onFlowExpired = onFlowExpired;
    }

    /**
     * Processes a parsed packet, associating it with an existing flow or creating a new one.
     * 
     * @param packet The packet to process.
     * @return The Flow this packet belongs to, or null if the packet lacks sufficient routing info (e.g., ARP).
     */
    public Flow processPacket(PacketInfo packet) {
        if (packet.getSrcIp() == null || packet.getDstIp() == null) {
            return null; // Cannot track flows for non-IP traffic like ARP
        }

        int srcPort = packet.getSrcPort() != null ? packet.getSrcPort() : 0;
        int dstPort = packet.getDstPort() != null ? packet.getDstPort() : 0;

        FlowKey key = new FlowKey(packet.getSrcIp(), packet.getDstIp(), srcPort, dstPort, packet.getProtocol());

        return activeFlows.compute(key, (k, existingFlow) -> {
            if (existingFlow == null) {
                return new Flow(packet, k);
            } else {
                existingFlow.addPacket(packet);
                return existingFlow;
            }
        });
    }

    /**
     * Iterates over tracked flows and removes any that have exceeded the idle timeout.
     * Should be called periodically.
     * 
     * @param currentTimeMillis The current time in milliseconds to compare against flow last-seen times.
     */
    public void cleanupStaleFlows(long currentTimeMillis) {
        Iterator<Map.Entry<FlowKey, Flow>> iterator = activeFlows.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FlowKey, Flow> entry = iterator.next();
            Flow flow = entry.getValue();
            
            if (currentTimeMillis - flow.getLastSeenTime() > flowTimeoutMillis) {
                if (onFlowExpired != null) {
                    onFlowExpired.accept(flow);
                }
                iterator.remove();
            }
        }
    }

    public int getActiveFlowCount() {
        return activeFlows.size();
    }
}
