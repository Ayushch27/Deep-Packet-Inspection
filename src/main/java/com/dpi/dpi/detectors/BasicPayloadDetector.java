package com.dpi.dpi.detectors;

import com.dpi.dpi.DetectionResult;
import com.dpi.dpi.ProtocolDetector;
import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;

import java.nio.charset.StandardCharsets;

/**
 * Basic DPI detector that inspects the start of the payload for protocol signatures.
 * Yields high confidence scores when specific signatures are matched.
 */
public class BasicPayloadDetector implements ProtocolDetector {

    @Override
    public DetectionResult detect(Flow flow, PacketInfo packet) {
        byte[] payload = packet.getPayload();
        
        if (payload == null || payload.length == 0) {
            return null;
        }

        // Try HTTP and SSH text signatures
        if (payload.length >= 4) {
            // Read first few bytes as ASCII
            String strStart = new String(payload, 0, Math.min(payload.length, 10), StandardCharsets.US_ASCII);
            
            if (strStart.startsWith("GET ") || strStart.startsWith("POST") ||
                strStart.startsWith("PUT ") || strStart.startsWith("HTTP/")) {
                return new DetectionResult("HTTP", 0.9, "Payload Signature");
            }
            
            if (strStart.startsWith("SSH-")) {
                return new DetectionResult("SSH", 0.9, "Payload Signature");
            }
        }

        // Try TLS / HTTPS Handshake signature
        // Content Type 22 (0x16) = Handshake, Version 3.x (0x03 0x01, 0x03 0x03, etc.)
        if (payload.length > 5 && payload[0] == 0x16 && payload[1] == 0x03) {
            return new DetectionResult("HTTPS/TLS", 0.85, "TLS Handshake Signature");
        }

        return null;
    }
}
