package com.dpi.export;

import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Exports filtered/allowed packets to a new PCAP file.
 * Thread-safe: only one thread should call write() at a time, or callers should synchronize externally.
 */
public class PcapExporter implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(PcapExporter.class);

    private PcapHandle handle;
    private PcapDumper dumpHandle;
    private final AtomicLong writtenPackets = new AtomicLong(0);

    /**
     * Opens a new PCAP dump file for writing.
     * 
     * @param outputPath Path to the output PCAP file.
     */
    public PcapExporter(String outputPath) {
        try {
            java.io.File file = new java.io.File(outputPath);
            if (file.getParentFile() != null) {
                file.getParentFile().mkdirs();
            }
            // Open a dead handle with Ethernet link type and max snaplen
            handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
            dumpHandle = handle.dumpOpen(outputPath);
            logger.info("PCAP exporter initialized. Writing to: {}", outputPath);
        } catch (PcapNativeException | org.pcap4j.core.NotOpenException e) {
            logger.error("Failed to open PCAP export file: {}", outputPath, e);
            handle = null;
            dumpHandle = null;
        }
    }

    /**
     * Writes a single packet to the output PCAP file.
     * 
     * @param packet The raw Pcap4J packet to write.
     */
    public synchronized void write(Packet packet) {
        if (dumpHandle == null) return;
        try {
            dumpHandle.dump(packet);
            writtenPackets.incrementAndGet();
        } catch (org.pcap4j.core.NotOpenException e) {
            logger.error("Dump handle not open for writing", e);
        }
    }

    public long getWrittenCount() {
        return writtenPackets.get();
    }

    @Override
    public void close() {
        if (dumpHandle != null) {
            dumpHandle.close();
        }
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
        logger.info("PCAP exporter closed. Total packets written: {}", writtenPackets.get());
    }
}
