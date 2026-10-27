package com.dpi.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Loads application properties for system configuration.
 */
public class AppConfig {
    private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);

    private int workers = 4;
    private int queueCapacity = 10000;

    public void load(String path) {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(path)) {
            props.load(fis);
            workers = Integer.parseInt(props.getProperty("workers", "4"));
            queueCapacity = Integer.parseInt(props.getProperty("queue.capacity", "10000"));
            logger.info("Loaded configuration from {}: workers={}, queueCapacity={}", path, workers, queueCapacity);
        } catch (IOException | NumberFormatException e) {
            logger.warn("Failed to load config from {}. Using defaults (workers={}, queueCapacity={})", path, workers, queueCapacity);
        }
    }

    public int getWorkers() { return workers; }
    public int getQueueCapacity() { return queueCapacity; }
}
