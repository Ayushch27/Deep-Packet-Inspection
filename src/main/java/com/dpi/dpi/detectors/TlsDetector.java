package com.dpi.dpi.detectors;

import com.dpi.dpi.DetectionResult;
import com.dpi.dpi.ProtocolDetector;
import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;
import com.dpi.model.TlsMetadata;

import java.nio.charset.StandardCharsets;

public class TlsDetector implements ProtocolDetector {

    @Override
    public DetectionResult detect(Flow flow, PacketInfo packet) {
        byte[] payload = packet.getPayload();
        if (payload == null || payload.length < 43) {
            return null;
        }

        // Check for TLS Handshake Record
        if (payload[0] != 0x16) return null; // 22 = Handshake
        
        // Version (e.g. 0x03 0x01 = TLS 1.0, 0x03 0x03 = TLS 1.2)
        if (payload[1] != 0x03) return null;

        // Check for Client Hello
        if (payload[5] != 0x01) {
            // It's TLS, but not a ClientHello. We might have missed the first packet.
            return new DetectionResult("HTTPS/TLS", 0.85, "TLS Record (Non-ClientHello)");
        }

        TlsMetadata metadata = flow.getTlsMetadata();
        if (metadata == null) {
            metadata = new TlsMetadata();
            flow.setTlsMetadata(metadata);
        }

        // Extract Version
        metadata.setTlsVersion(String.format("TLS 1.%d", payload[10] - 1));

        try {
            int offset = 43; // Past Random
            
            // Skip Session ID
            int sessionIdLen = payload[offset] & 0xFF;
            offset += 1 + sessionIdLen;
            
            // Skip Cipher Suites
            int cipherSuitesLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            offset += 2 + cipherSuitesLen;
            
            // Skip Compression Methods
            int compMethodsLen = payload[offset] & 0xFF;
            offset += 1 + compMethodsLen;
            
            // Now at Extensions (if any)
            if (offset + 2 <= payload.length) {
                int extensionsLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
                offset += 2;
                
                int endOffset = offset + extensionsLen;
                while (offset + 4 <= endOffset && offset + 4 <= payload.length) {
                    int extType = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
                    int extLen = ((payload[offset + 2] & 0xFF) << 8) | (payload[offset + 3] & 0xFF);
                    offset += 4;
                    
                    if (extType == 0x0000) { // Server Name Indication (SNI)
                        // SNI List Length (2) -> Server Name Type (1) -> Server Name Length (2) -> Server Name
                        if (extLen > 5) {
                            int nameLen = ((payload[offset + 3] & 0xFF) << 8) | (payload[offset + 4] & 0xFF);
                            if (nameLen > 0 && offset + 5 + nameLen <= payload.length) {
                                String sni = new String(payload, offset + 5, nameLen, StandardCharsets.UTF_8);
                                metadata.setSni(sni);
                            }
                        }
                    } else if (extType == 0x0010) { // ALPN
                        // ALPN Extension Length (2) -> String Length (1) -> String
                        if (extLen > 3) {
                            int alpnLen = payload[offset + 2] & 0xFF;
                            if (alpnLen > 0 && offset + 3 + alpnLen <= payload.length) {
                                String alpn = new String(payload, offset + 3, alpnLen, StandardCharsets.UTF_8);
                                metadata.setAlpn(alpn);
                            }
                        }
                    }
                    
                    offset += extLen;
                }
            }
        } catch (Exception e) {
            // Malformed packet or incorrect offsets due to fragmentation, safely ignore
        }

        return new DetectionResult("HTTPS/TLS", 0.95, "TLS ClientHello Parsing");
    }
}
