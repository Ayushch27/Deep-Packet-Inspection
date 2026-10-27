package com.dpi.capture;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.function.Consumer;

/**
 * Implementation of PacketSource that captures live network traffic from a specified interface.
 */
public class LiveNetworkSource implements PacketSource {
    private static final Logger logger = LoggerFactory.getLogger(LiveNetworkSource.class);
    private final String interfaceName;
    private PcapHandle handle;
    private volatile boolean running = false;

    // Typical MTU snap length, allowing us to capture whole packets
    private static final int SNAPLEN = 65536;
    // Read timeout helps the capture loop remain responsive to shutdown signals during idle periods
    private static final int READ_TIMEOUT_MS = 1000;

    public LiveNetworkSource(String interfaceName) {
        this.interfaceName = interfaceName;
    }

    @Override
    public void start(Consumer<Packet> packetConsumer) throws PcapNativeException, NotOpenException, InterruptedException {
        logger.info("Initializing live capture on interface: {}", interfaceName);
        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);

        if (nif == null) {
            logger.error("Network interface not found: {}", interfaceName);
            throw new IllegalArgumentException("No such network interface: " + interfaceName);
        }

        logger.info("Opening interface: {} ({})", nif.getName(), nif.getDescription());

        handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS);
        running = true;

        logger.info("Started live packet capture...");

        try {
            while (running) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    if (packet != null) {
                        packetConsumer.accept(packet);
                    }
                } catch (java.util.concurrent.TimeoutException e) {
                    // This is expected and normal when no packets arrive within READ_TIMEOUT_MS.
                    // It allows the while loop to check the 'running' condition and gracefully stop.
                } catch (java.io.EOFException e) {
                    logger.warn("EOF unexpectedly reached on live capture stream.");
                    break;
                }
            }
        } finally {
            running = false;
            logger.info("Live packet capture stopped.");
        }
    }

    @Override
    public void stop() {
        running = false;
        if (handle != null) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                logger.warn("Handle already closed or not open when trying to break loop", e);
            }
        }
    }

    @Override
    public void close() {
        stop();
        if (handle != null && handle.isOpen()) {
            handle.close();
            logger.info("Live capture handle closed.");
        }
    }

    /**
     * Utility method to print all available network interfaces for the user.
     */
    public static void listInterfaces() {
        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (allDevs == null || allDevs.isEmpty()) {
                System.out.println("No network interfaces found. (Check permissions/admin rights or Npcap/libpcap installation)");
                return;
            }
            
            System.out.println("Available Network Interfaces:");
            for (PcapNetworkInterface dev : allDevs) {
                System.out.printf(" - %s\n", dev.getName());
                System.out.printf("     Description: %s\n", dev.getDescription() != null ? dev.getDescription() : "None");
                
                for (PcapAddress addr : dev.getAddresses()) {
                    if (addr.getAddress() != null) {
                        System.out.printf("     IP: %s\n", addr.getAddress().getHostAddress());
                    }
                }
                System.out.println();
            }
        } catch (PcapNativeException e) {
            System.err.println("Error enumerating interfaces: " + e.getMessage());
            System.err.println("Please ensure Npcap (Windows) or libpcap (Linux) is correctly installed.");
        }
    }
}
