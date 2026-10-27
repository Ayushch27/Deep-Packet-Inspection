package com.dpi.rules;

import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

/**
 * Evaluates packets and flows against configurable user rules.
 */
public class RuleEngine {
    private static final Logger logger = LoggerFactory.getLogger(RuleEngine.class);
    private RuleConfig config;

    public RuleEngine(String configPath) {
        ObjectMapper mapper = new ObjectMapper();
        File file = new File(configPath);
        if (file.exists()) {
            try {
                config = mapper.readValue(file, RuleConfig.class);
                logger.info("Successfully loaded rules from {}", configPath);
            } catch (IOException e) {
                logger.error("Failed to parse {}. Using empty rules.", configPath, e);
                config = new RuleConfig();
            }
        } else {
            logger.warn("Rule config file not found at {}. Using empty rules.", configPath);
            config = new RuleConfig();
        }
    }

    /**
     * Evaluates a packet/flow against the loaded rules to determine the action.
     */
    public RuleAction evaluate(PacketInfo packet, Flow flow) {
        String srcIp = packet.getSrcIp();
        String dstIp = packet.getDstIp();

        // 1. IP Blocklist Evaluation
        if (config.block_ips != null && (config.block_ips.contains(srcIp) || config.block_ips.contains(dstIp))) {
            return RuleAction.BLOCK;
        }

        // 2. Domain Blocklist Evaluation (Requires Flow DPI Metadata)
        if (flow != null && config.block_domains != null) {
            String domain = extractDomain(flow);
            if (domain != null) {
                boolean isBlocked = config.block_domains.stream().anyMatch(blockedDomain -> 
                    domain.equalsIgnoreCase(blockedDomain) || domain.endsWith("." + blockedDomain)
                );
                if (isBlocked) {
                    return RuleAction.BLOCK;
                }
            }
        }
        
        // 3. Allowlist Evaluation 
        // If an allow_ips list is strictly defined, everything else should theoretically be blocked.
        // For DPI/monitoring use cases, we default to ALLOW unless explicitly blocked.
        if (config.allow_ips != null && !config.allow_ips.isEmpty()) {
            if (!config.allow_ips.contains(srcIp) && !config.allow_ips.contains(dstIp)) {
                return RuleAction.BLOCK; 
            }
        }

        return RuleAction.ALLOW;
    }

    private String extractDomain(Flow flow) {
        if (flow.getTlsMetadata() != null && flow.getTlsMetadata().getSni() != null) {
            return flow.getTlsMetadata().getSni();
        }
        if (flow.getHttpMetadata() != null && flow.getHttpMetadata().getHost() != null) {
            return flow.getHttpMetadata().getHost();
        }
        if (flow.getDnsMetadata() != null && flow.getDnsMetadata().getQueryName() != null) {
            return flow.getDnsMetadata().getQueryName();
        }
        return null;
    }
}
