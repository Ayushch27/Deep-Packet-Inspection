package com.dpi.capture;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Consumer;

/**
 * Implementation of PacketSource that reads packets sequentially from an offline PCAP file.
 */
public class PcapFileSource implements PacketSource {
    private static final Logger logger = LoggerFactory.getLogger(PcapFileSource.class);
    private final String filePath;
    private PcapHandle handle;
    private volatile boolean running = false;

    public PcapFileSource(String filePath) {
        this.filePath = filePath;
    }

    @Override
    public void start(Consumer<Packet> packetConsumer) throws PcapNativeException, NotOpenException, InterruptedException {
        logger.info("Opening offline PCAP file: {}", filePath);
        
        try {
            handle = Pcaps.openOffline(filePath);
        } catch (PcapNativeException e) {
            logger.error("Failed to open PCAP file: {}", filePath, e);
            throw e;
        }

        running = true;
        logger.info("Starting packet processing from PCAP file...");

        try {
            while (running) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    if (packet != null) {
                        packetConsumer.accept(packet);
                    }
                } catch (java.util.concurrent.TimeoutException e) {
                    // Ignore timeout and continue
                } catch (java.io.EOFException e) {
                    // End of file reached
                    break;
                }
            }
        } finally {
            running = false;
            logger.info("Finished reading PCAP file.");
        }
    }

    @Override
    public void stop() {
        running = false;
        if (handle != null) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                logger.warn("PcapHandle was not open when trying to break loop", e);
            }
        }
    }

    @Override
    public void close() {
        stop();
        if (handle != null && handle.isOpen()) {
            handle.close();
            logger.info("PCAP handle closed.");
        }
    }
}
