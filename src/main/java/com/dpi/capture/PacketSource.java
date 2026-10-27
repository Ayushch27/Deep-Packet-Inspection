package com.dpi.capture;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

import java.util.function.Consumer;

/**
 * Interface representing a source of network packets.
 * This can be implemented by an offline PCAP reader or a live network interface capture.
 */
public interface PacketSource extends AutoCloseable {
    
    /**
     * Starts capturing/reading packets and passing them to the provided consumer.
     * 
     * @param packetConsumer The callback that receives captured packets.
     * @throws PcapNativeException If an error occurs in the underlying pcap library.
     * @throws NotOpenException If the capture handle is not properly opened.
     * @throws InterruptedException If the capture loop is interrupted.
     */
    void start(Consumer<Packet> packetConsumer) throws PcapNativeException, NotOpenException, InterruptedException;
    
    /**
     * Signals the capture loop to stop.
     */
    void stop();
    
    @Override
    void close();
}
