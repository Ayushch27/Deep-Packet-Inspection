package com.dpi;

import com.dpi.capture.PacketSource;
import com.dpi.capture.PcapFileSource;
import com.dpi.cli.Dashboard;
import com.dpi.statistics.StatsEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.concurrent.atomic.AtomicLong;

public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        logger.info("Starting Java Deep Packet Inspection Engine...");
        
        String pcapFile = null;
        String interfaceName = null;
        String outputPcap = null;
        boolean listInterfaces = false;
        java.util.List<String> rawFilters = new java.util.ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            if ("--list-interfaces".equals(args[i])) {
                listInterfaces = true;
            } else if ("--pcap".equals(args[i]) && i + 1 < args.length) {
                pcapFile = args[i + 1];
                i++;
            } else if ("--interface".equals(args[i]) && i + 1 < args.length) {
                interfaceName = args[i + 1];
                i++;
            } else if ("--filter".equals(args[i]) && i + 1 < args.length) {
                rawFilters.add(args[i + 1]);
                i++;
            } else if ("--output".equals(args[i]) && i + 1 < args.length) {
                outputPcap = args[i + 1];
                i++;
            }
        }

        if (listInterfaces) {
            com.dpi.capture.LiveNetworkSource.listInterfaces();
            return;
        }

        if (pcapFile == null && interfaceName == null) {
            System.out.println("========================================================");
            System.out.println("        JAVA DEEP PACKET INSPECTION ENGINE              ");
            System.out.println("========================================================");
            System.out.println("Usage:");
            System.out.println("  java -jar dpi.jar --pcap <file.pcap>");
            System.out.println("  java -jar dpi.jar --interface <name>");
            System.out.println("  java -jar dpi.jar --list-interfaces");
            System.out.println("  java -jar dpi.jar --pcap <file> --output <filtered.pcap>");
            System.out.println("  java -jar dpi.jar --pcap <file> --filter \"protocol=TCP\" --filter \"port=443\"");
            return;
        }
        
        java.util.List<com.dpi.rules.PacketFilter> cliFilters = rawFilters.stream()
                .map(com.dpi.rules.PacketFilter::new).toList();
        com.dpi.rules.RuleEngine ruleEngine = new com.dpi.rules.RuleEngine("config/rules.json");

        // Determine mode and source
        String mode;
        String inputLabel;
        PacketSource source;
        if (pcapFile != null) {
            mode = "PCAP Offline";
            inputLabel = pcapFile;
            source = new PcapFileSource(pcapFile);
        } else {
            mode = "LIVE CAPTURE";
            inputLabel = interfaceName;
            source = new com.dpi.capture.LiveNetworkSource(interfaceName);
        }

        com.dpi.export.PcapExporter exporter = (outputPcap != null) ? new com.dpi.export.PcapExporter(outputPcap) : null;

        com.dpi.config.AppConfig appConfig = new com.dpi.config.AppConfig();
        appConfig.load("config/application.properties");

        // Core components
        StatsEngine stats = new StatsEngine();
        AtomicLong packetCount = new AtomicLong(0);
        com.dpi.storage.DatabaseManager db = new com.dpi.storage.DatabaseManager("data/dpi.db");

        com.dpi.flow.FlowTracker flowTracker = new com.dpi.flow.FlowTracker(60, expiredFlow -> {
            stats.recordFlowExpired();
            db.saveFlow(expiredFlow);
            logger.debug("Flow Expired: {} (App: {})", expiredFlow.getFlowId(), expiredFlow.getApplicationProtocol());
        });
        
        com.dpi.dpi.DPIEngine dpiEngine = new com.dpi.dpi.DPIEngine();

        Dashboard dashboard = new Dashboard(stats, mode, inputLabel, appConfig.getWorkers());

        com.dpi.detection.ThreatDetectionEngine threatEngine = new com.dpi.detection.ThreatDetectionEngine(threat -> {
            stats.recordThreat();
            dashboard.addAlert(threat);
            db.saveThreat(threat);
            logger.warn("[SECURITY ALERT] {}", threat.toString());
        });
        
        threatEngine.addDetector(new com.dpi.detection.detectors.PortScanDetector(20, 10));
        threatEngine.addDetector(new com.dpi.detection.detectors.FloodDetector("TCP", true, 1000, 5, "SYN Flood", com.dpi.detection.ThreatSeverity.HIGH));
        threatEngine.addDetector(new com.dpi.detection.detectors.FloodDetector("ICMP", false, 500, 5, "ICMP Flood", com.dpi.detection.ThreatSeverity.MEDIUM));

        // Worker pool: each worker processes a packet through Flow -> DPI -> Threats -> Rules
        com.dpi.processing.WorkerPool workerPool = new com.dpi.processing.WorkerPool(appConfig.getWorkers(), appConfig.getQueueCapacity(), info -> {
            stats.recordPacket(info.getProtocol(), info.getPacketLength());

            com.dpi.flow.Flow flow = flowTracker.processPacket(info);
            if (flow != null && flow.getTotalPackets() == 1) {
                stats.recordFlowCreated();
            }
            
            // DPI Analysis
            if (flow != null) {
                dpiEngine.analyze(flow, info);
                stats.recordAppProtocol(flow.getApplicationProtocol());
            }

            // CLI Filtering
            for (com.dpi.rules.PacketFilter pf : cliFilters) {
                if (!pf.matches(info, flow)) {
                    return;
                }
            }
            
            // Threats
            threatEngine.analyze(info, flow);
            
            // Rules
            com.dpi.rules.RuleAction action = ruleEngine.evaluate(info, flow);
            if (action == com.dpi.rules.RuleAction.BLOCK) {
                stats.recordBlocked();
                if (flow != null && !flow.isBlockAlerted()) {
                    logger.warn("[RULE ENGINE] BLOCKED Flow: {} -> {}", info.getSrcIp(), info.getDstIp());
                    flow.setBlockAlerted(true);
                }
                return;
            }
            stats.recordAllowed();

            // Export allowed packet if exporter configured
            if (exporter != null && info.getRawPacket() != null) {
                exporter.write(info.getRawPacket());
            }
        });

        stats.resetStartTime();

        // Optional periodic dashboard for live capture
        java.util.concurrent.ScheduledExecutorService liveDashboardScheduler = null;
        if (pcapFile == null) {
            liveDashboardScheduler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "dashboard-refresh");
                t.setDaemon(true);
                return t;
            });
            liveDashboardScheduler.scheduleAtFixedRate(() -> {
                System.out.println(dashboard.render());
            }, 5, 5, java.util.concurrent.TimeUnit.SECONDS);
        }

        final java.util.concurrent.ScheduledExecutorService schedulerRef = liveDashboardScheduler;
        java.util.concurrent.atomic.AtomicBoolean shutdownInitiated = new java.util.concurrent.atomic.AtomicBoolean(false);
        Runnable cleanupAction = () -> {
            if (!shutdownInitiated.compareAndSet(false, true)) {
                return;
            }
            logger.info("Shutting down DPI engine...");
            if (schedulerRef != null) {
                schedulerRef.shutdownNow();
            }
            try {
                source.stop();
            } catch (Exception e) {
                logger.error("Error stopping packet source: ", e);
            }
            try {
                workerPool.shutdownAndWait();
            } catch (Exception e) {
                logger.error("Error shutting down worker pool: ", e);
            }
            try {
                flowTracker.cleanupStaleFlows(Long.MAX_VALUE);
            } catch (Exception e) {
                logger.error("Error cleaning up flows: ", e);
            }
            if (exporter != null) {
                try {
                    exporter.close();
                } catch (Exception e) {
                    logger.error("Error closing PCAP exporter: ", e);
                }
            }
            try {
                source.close();
            } catch (Exception e) {
                logger.error("Error closing capture source: ", e);
            }
            try {
                db.close();
            } catch (Exception e) {
                logger.error("Error closing database: ", e);
            }

            // Print final dashboard
            System.out.println(dashboard.render());
            System.out.println("Total packets captured: " + packetCount.get());
            if (exporter != null) {
                System.out.println("Total packets exported: " + exporter.getWrittenCount());
            }
        };

        Thread shutdownHook = new Thread(cleanupAction, "dpi-shutdown-hook");
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        try {
            source.start(packet -> {
                long count = packetCount.incrementAndGet();
                com.dpi.model.PacketInfo info = com.dpi.parser.PacketParser.parse(packet);
                workerPool.dispatch(info);
                
                if (count % 5000 == 0) {
                    flowTracker.cleanupStaleFlows(info.getTimestamp());
                }
            });
        } catch (Exception e) {
            logger.error("Error during packet capture: ", e);
        } finally {
            cleanupAction.run();
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException ignored) {
                // JVM already shutting down
            }
        }
    }
}
