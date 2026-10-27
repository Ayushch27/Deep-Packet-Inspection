package com.dpi.dpi.detectors;

import com.dpi.dpi.DetectionResult;
import com.dpi.dpi.ProtocolDetector;
import com.dpi.flow.Flow;
import com.dpi.model.DnsMetadata;
import com.dpi.model.PacketInfo;

import java.nio.charset.StandardCharsets;

public class DnsDetector implements ProtocolDetector {

    @Override
    public DetectionResult detect(Flow flow, PacketInfo packet) {
        // DNS typically runs over UDP port 53. Check port to minimize false positives 
        // since we are manually parsing generic binary data.
        if (packet.getSrcPort() != 53 && packet.getDstPort() != 53) {
            return null;
        }

        byte[] payload = packet.getPayload();
        if (payload == null || payload.length < 12) {
            return null;
        }

        try {
            int transactionId = ((payload[0] & 0xFF) << 8) | (payload[1] & 0xFF);
            int flags = ((payload[2] & 0xFF) << 8) | (payload[3] & 0xFF);
            int questions = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
            int answerRRs = ((payload[6] & 0xFF) << 8) | (payload[7] & 0xFF);
            
            boolean isResponse = (flags & 0x8000) != 0;
            int rcode = flags & 0x000F;

            DnsMetadata metadata = flow.getDnsMetadata();
            if (metadata == null) {
                metadata = new DnsMetadata();
                metadata.setTransactionId(transactionId);
                flow.setDnsMetadata(metadata);
            }

            if (isResponse) {
                metadata.setResponseCode(rcode);
                metadata.setAnswerCount(answerRRs);
            }

            // Parse QNAME if present and not already parsed
            if (questions > 0 && metadata.getQueryName() == null) {
                int offset = 12;
                StringBuilder qname = new StringBuilder();
                
                while (offset < payload.length) {
                    int len = payload[offset++] & 0xFF;
                    if (len == 0) break; // End of QNAME
                    
                    if ((len & 0xC0) == 0xC0) {
                        // DNS pointer compression (ignore for now to keep parsing simple/safe)
                        break; 
                    }
                    
                    if (offset + len <= payload.length) {
                        if (qname.length() > 0) qname.append(".");
                        qname.append(new String(payload, offset, len, StandardCharsets.US_ASCII));
                        offset += len;
                    } else {
                        break;
                    }
                }
                
                metadata.setQueryName(qname.toString());
                
                // Read QTYPE
                if (offset + 2 <= payload.length) {
                    int qtype = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
                    metadata.setQueryType(getDnsRecordType(qtype));
                }
            }
            
            return new DetectionResult("DNS", 0.95, "DNS Protocol Parsing");
            
        } catch (Exception e) {
            // Malformed packet
        }

        return null;
    }

    private String getDnsRecordType(int type) {
        return switch (type) {
            case 1 -> "A";
            case 2 -> "NS";
            case 5 -> "CNAME";
            case 15 -> "MX";
            case 16 -> "TXT";
            case 28 -> "AAAA";
            case 255 -> "ANY";
            default -> "TYPE" + type;
        };
    }
}
