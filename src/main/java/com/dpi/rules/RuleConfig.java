package com.dpi.rules;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RuleConfig {
    public List<String> block_ips;
    public List<String> allow_ips;
    public List<String> block_domains;
    public List<String> allow_domains;
    public Map<String, Boolean> alert_rules;

    // Optional default constructor for Jackson
    public RuleConfig() {}
}
