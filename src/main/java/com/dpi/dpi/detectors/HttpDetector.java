package com.dpi.dpi.detectors;

import com.dpi.dpi.DetectionResult;
import com.dpi.dpi.ProtocolDetector;
import com.dpi.flow.Flow;
import com.dpi.model.HttpMetadata;
import com.dpi.model.PacketInfo;

import java.nio.charset.StandardCharsets;

public class HttpDetector implements ProtocolDetector {

    @Override
    public DetectionResult detect(Flow flow, PacketInfo packet) {
        byte[] payload = packet.getPayload();
        if (payload == null || payload.length < 10) return null;

        String data = new String(payload, StandardCharsets.UTF_8);
        
        // Basic check for Request or Response
        boolean isRequest = data.startsWith("GET ") || data.startsWith("POST ") || 
                            data.startsWith("PUT ") || data.startsWith("DELETE ") || 
                            data.startsWith("HEAD ") || data.startsWith("OPTIONS ");
                            
        boolean isResponse = data.startsWith("HTTP/");

        if (isRequest || isResponse) {
            HttpMetadata metadata = flow.getHttpMetadata();
            if (metadata == null) {
                metadata = new HttpMetadata();
                flow.setHttpMetadata(metadata);
            }

            String[] lines = data.split("\r\n");
            if (lines.length > 0) {
                String firstLine = lines[0];
                if (isRequest && metadata.getMethod() == null) {
                    String[] parts = firstLine.split(" ");
                    if (parts.length >= 2) {
                        metadata.setMethod(parts[0]);
                        metadata.setUri(parts[1]);
                    }
                } else if (isResponse && metadata.getStatusCode() == null) {
                    String[] parts = firstLine.split(" ");
                    if (parts.length >= 2) {
                        try {
                            metadata.setStatusCode(Integer.parseInt(parts[1]));
                        } catch (NumberFormatException ignored) {}
                    }
                }

                // Parse headers
                for (int i = 1; i < lines.length; i++) {
                    String line = lines[i];
                    if (line.isEmpty()) break; // End of headers
                    
                    int colonIdx = line.indexOf(':');
                    if (colonIdx > 0) {
                        String key = line.substring(0, colonIdx).trim().toLowerCase();
                        String value = line.substring(colonIdx + 1).trim();
                        
                        if (key.equals("host") && metadata.getHost() == null) {
                            metadata.setHost(value);
                        } else if (key.equals("user-agent") && metadata.getUserAgent() == null) {
                            metadata.setUserAgent(value);
                        } else if (key.equals("content-type") && metadata.getContentType() == null) {
                            metadata.setContentType(value);
                        }
                    }
                }
            }
            return new DetectionResult("HTTP", 0.95, "HTTP Header Parsing");
        }

        return null;
    }
}
