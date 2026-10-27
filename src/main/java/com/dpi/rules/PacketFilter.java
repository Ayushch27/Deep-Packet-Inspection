package com.dpi.rules;

import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;

/**
 * Represents a command-line packet filter to restrict which traffic is logged or processed.
 */
public class PacketFilter {
    private final String key;
    private final String value;

    public PacketFilter(String filterStr) {
        String[] parts = filterStr.split("=", 2);
        this.key = parts[0].trim().toLowerCase();
        this.value = parts.length > 1 ? parts[1].trim() : "";
    }

    /**
     * Tests whether the provided packet/flow matches the filter criteria.
     */
    public boolean matches(PacketInfo packet, Flow flow) {
        return switch (key) {
            case "protocol" -> value.equalsIgnoreCase(packet.getProtocol());
            case "port" -> {
                try {
                    int p = Integer.parseInt(value);
                    yield (packet.getSrcPort() != null && packet.getSrcPort() == p) ||
                          (packet.getDstPort() != null && packet.getDstPort() == p);
                } catch (NumberFormatException e) {
                    yield false;
                }
            }
            case "src" -> value.equals(packet.getSrcIp());
            case "dst" -> value.equals(packet.getDstIp());
            case "app" -> flow != null && value.equalsIgnoreCase(flow.getApplicationProtocol());
            default -> true; // Unknown filter keys allow traffic by default
        };
    }
}
