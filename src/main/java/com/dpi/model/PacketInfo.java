package com.dpi.model;

/**
 * Immutable domain model representing a normalized network packet.
 * This decouples the core DPI engine from the specific Pcap4J packet representations.
 */
public class PacketInfo {
    private final long timestamp;
    private final String srcMac;
    private final String dstMac;
    private final String srcIp;
    private final String dstIp;
    private final Integer srcPort;
    private final Integer dstPort;
    private final String protocol;
    private final int packetLength;
    private final int payloadLength;
    private final int ttl;
    private final int tcpFlags;
    private final byte[] payload;
    private final org.pcap4j.packet.Packet rawPacket;

    private PacketInfo(Builder builder) {
        this.timestamp = builder.timestamp;
        this.srcMac = builder.srcMac;
        this.dstMac = builder.dstMac;
        this.srcIp = builder.srcIp;
        this.dstIp = builder.dstIp;
        this.srcPort = builder.srcPort;
        this.dstPort = builder.dstPort;
        this.protocol = builder.protocol;
        this.packetLength = builder.packetLength;
        this.payloadLength = builder.payloadLength;
        this.ttl = builder.ttl;
        this.tcpFlags = builder.tcpFlags;
        this.payload = builder.payload;
        this.rawPacket = builder.rawPacket;
    }

    public long getTimestamp() { return timestamp; }
    public String getSrcMac() { return srcMac; }
    public String getDstMac() { return dstMac; }
    public String getSrcIp() { return srcIp; }
    public String getDstIp() { return dstIp; }
    public Integer getSrcPort() { return srcPort; }
    public Integer getDstPort() { return dstPort; }
    public String getProtocol() { return protocol; }
    public int getPacketLength() { return packetLength; }
    public int getPayloadLength() { return payloadLength; }
    public int getTtl() { return ttl; }
    public int getTcpFlags() { return tcpFlags; }
    public byte[] getPayload() { return payload; }
    public org.pcap4j.packet.Packet getRawPacket() { return rawPacket; }

    public static class Builder {
        private long timestamp;
        private String srcMac;
        private String dstMac;
        private String srcIp;
        private String dstIp;
        private Integer srcPort;
        private Integer dstPort;
        private String protocol = "Unknown";
        private int packetLength;
        private int payloadLength;
        private int ttl;
        private int tcpFlags;
        private byte[] payload;
        private org.pcap4j.packet.Packet rawPacket;

        public Builder timestamp(long timestamp) { this.timestamp = timestamp; return this; }
        public Builder srcMac(String srcMac) { this.srcMac = srcMac; return this; }
        public Builder dstMac(String dstMac) { this.dstMac = dstMac; return this; }
        public Builder srcIp(String srcIp) { this.srcIp = srcIp; return this; }
        public Builder dstIp(String dstIp) { this.dstIp = dstIp; return this; }
        public Builder srcPort(Integer srcPort) { this.srcPort = srcPort; return this; }
        public Builder dstPort(Integer dstPort) { this.dstPort = dstPort; return this; }
        public Builder protocol(String protocol) { this.protocol = protocol; return this; }
        public Builder packetLength(int packetLength) { this.packetLength = packetLength; return this; }
        public Builder payloadLength(int payloadLength) { this.payloadLength = payloadLength; return this; }
        public Builder ttl(int ttl) { this.ttl = ttl; return this; }
        public Builder tcpFlags(int tcpFlags) { this.tcpFlags = tcpFlags; return this; }
        public Builder payload(byte[] payload) { this.payload = payload; return this; }
        public Builder rawPacket(org.pcap4j.packet.Packet rawPacket) { this.rawPacket = rawPacket; return this; }

        public PacketInfo build() {
            return new PacketInfo(this);
        }
    }
}
