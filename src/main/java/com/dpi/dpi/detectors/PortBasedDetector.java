package com.dpi.dpi.detectors;

import com.dpi.dpi.DetectionResult;
import com.dpi.dpi.ProtocolDetector;
import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;

/**
 * Basic DPI detector that infers application protocols based on well-known ports.
 * Yields low confidence scores since ports can be spoofed or reused.
 */
public class PortBasedDetector implements ProtocolDetector {

    @Override
    public DetectionResult detect(Flow flow, PacketInfo packet) {
        int srcPort = flow.getSourcePort();
        int dstPort = flow.getDestinationPort();

        if (checkPort(srcPort, dstPort, 80) || checkPort(srcPort, dstPort, 8080)) {
            return new DetectionResult("HTTP", 0.4, "Port Heuristics");
        } else if (checkPort(srcPort, dstPort, 443) || checkPort(srcPort, dstPort, 8443)) {
            return new DetectionResult("HTTPS/TLS", 0.4, "Port Heuristics");
        } else if (checkPort(srcPort, dstPort, 53)) {
            return new DetectionResult("DNS", 0.4, "Port Heuristics");
        } else if (checkPort(srcPort, dstPort, 22)) {
            return new DetectionResult("SSH", 0.5, "Port Heuristics");
        } else if (checkPort(srcPort, dstPort, 21)) {
            return new DetectionResult("FTP", 0.4, "Port Heuristics");
        } else if (checkPort(srcPort, dstPort, 25) || checkPort(srcPort, dstPort, 587)) {
            return new DetectionResult("SMTP", 0.4, "Port Heuristics");
        } else if (checkPort(srcPort, dstPort, 110)) {
            return new DetectionResult("POP3", 0.4, "Port Heuristics");
        } else if (checkPort(srcPort, dstPort, 143) || checkPort(srcPort, dstPort, 993)) {
            return new DetectionResult("IMAP", 0.4, "Port Heuristics");
        } else if (checkPort(srcPort, dstPort, 67) || checkPort(srcPort, dstPort, 68)) {
            return new DetectionResult("DHCP", 0.5, "Port Heuristics");
        }

        return null;
    }

    private boolean checkPort(int p1, int p2, int target) {
        return p1 == target || p2 == target;
    }
}
