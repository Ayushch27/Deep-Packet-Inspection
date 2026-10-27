package com.dpi.storage;

import com.dpi.detection.ThreatResult;
import com.dpi.flow.Flow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;

/**
 * SQLite-backed persistence layer for storing flow metadata, threat alerts, and DNS/HTTP/TLS records.
 */
public class DatabaseManager implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseManager.class);
    private Connection connection;

    public DatabaseManager(String dbPath) {
        try {
            java.io.File file = new java.io.File(dbPath);
            if (file.getParentFile() != null) {
                file.getParentFile().mkdirs();
            }
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            connection.setAutoCommit(false);
            initializeTables();
            logger.info("Database initialized at {}", dbPath);
        } catch (SQLException e) {
            logger.error("Failed to initialize database at {}", dbPath, e);
        }
    }

    private void initializeTables() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    app_protocol TEXT,
                    start_time INTEGER,
                    last_seen INTEGER,
                    duration_ms INTEGER,
                    packets_fwd INTEGER,
                    packets_rev INTEGER,
                    bytes_fwd INTEGER,
                    bytes_rev INTEGER,
                    risk_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    severity TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    evidence TEXT,
                    confidence REAL,
                    event_time INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    transaction_id INTEGER,
                    query_name TEXT,
                    query_type TEXT,
                    response_code INTEGER,
                    answer_count INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS http_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    method TEXT,
                    uri TEXT,
                    host TEXT,
                    user_agent TEXT,
                    status_code INTEGER,
                    content_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS tls_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    tls_version TEXT,
                    sni TEXT,
                    alpn TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """);

            connection.commit();
        }
    }

    /**
     * Persists a completed flow and its associated metadata records.
     */
    public synchronized void saveFlow(Flow flow) {
        if (connection == null) return;
        try {
            try (PreparedStatement ps = connection.prepareStatement(
                "INSERT INTO flows (flow_id, src_ip, dst_ip, src_port, dst_port, protocol, app_protocol, " +
                "start_time, last_seen, duration_ms, packets_fwd, packets_rev, bytes_fwd, bytes_rev, risk_score) " +
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
                ps.setString(1, flow.getFlowId());
                ps.setString(2, flow.getSourceIp());
                ps.setString(3, flow.getDestinationIp());
                ps.setInt(4, flow.getSourcePort());
                ps.setInt(5, flow.getDestinationPort());
                ps.setString(6, flow.getProtocol());
                ps.setString(7, flow.getApplicationProtocol());
                ps.setLong(8, flow.getStartTime());
                ps.setLong(9, flow.getLastSeenTime());
                ps.setLong(10, flow.getDuration());
                ps.setLong(11, flow.getPacketsForward());
                ps.setLong(12, flow.getPacketsReverse());
                ps.setLong(13, flow.getBytesForward());
                ps.setLong(14, flow.getBytesReverse());
                ps.setDouble(15, flow.getRiskScore());
                ps.executeUpdate();
            }

            // Save DNS metadata if present
            if (flow.getDnsMetadata() != null) {
                try (PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO dns_records (flow_id, transaction_id, query_name, query_type, response_code, answer_count) VALUES (?,?,?,?,?,?)")) {
                    ps.setString(1, flow.getFlowId());
                    ps.setInt(2, flow.getDnsMetadata().getTransactionId());
                    ps.setString(3, flow.getDnsMetadata().getQueryName());
                    ps.setString(4, flow.getDnsMetadata().getQueryType());
                    ps.setInt(5, flow.getDnsMetadata().getResponseCode());
                    ps.setInt(6, flow.getDnsMetadata().getAnswerCount());
                    ps.executeUpdate();
                }
            }

            // Save HTTP metadata if present
            if (flow.getHttpMetadata() != null) {
                try (PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO http_records (flow_id, method, uri, host, user_agent, status_code, content_type) VALUES (?,?,?,?,?,?,?)")) {
                    ps.setString(1, flow.getFlowId());
                    ps.setString(2, flow.getHttpMetadata().getMethod());
                    ps.setString(3, flow.getHttpMetadata().getUri());
                    ps.setString(4, flow.getHttpMetadata().getHost());
                    ps.setString(5, flow.getHttpMetadata().getUserAgent());
                    if (flow.getHttpMetadata().getStatusCode() != null) {
                        ps.setInt(6, flow.getHttpMetadata().getStatusCode());
                    } else {
                        ps.setNull(6, Types.INTEGER);
                    }
                    ps.setString(7, flow.getHttpMetadata().getContentType());
                    ps.executeUpdate();
                }
            }

            // Save TLS metadata if present
            if (flow.getTlsMetadata() != null) {
                try (PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO tls_records (flow_id, tls_version, sni, alpn) VALUES (?,?,?,?)")) {
                    ps.setString(1, flow.getFlowId());
                    ps.setString(2, flow.getTlsMetadata().getTlsVersion());
                    ps.setString(3, flow.getTlsMetadata().getSni());
                    ps.setString(4, flow.getTlsMetadata().getAlpn());
                    ps.executeUpdate();
                }
            }

            connection.commit();
        } catch (SQLException e) {
            logger.error("Failed to save flow {}", flow.getFlowId(), e);
            try { connection.rollback(); } catch (SQLException re) { /* ignored */ }
        }
    }

    /**
     * Persists a threat alert.
     */
    public synchronized void saveThreat(ThreatResult threat) {
        if (connection == null) return;
        try (PreparedStatement ps = connection.prepareStatement(
            "INSERT INTO threats (type, severity, src_ip, dst_ip, evidence, confidence, event_time) VALUES (?,?,?,?,?,?,?)")) {
            ps.setString(1, threat.getType());
            ps.setString(2, threat.getSeverity().name());
            ps.setString(3, threat.getSourceIp());
            ps.setString(4, threat.getDestinationIp());
            ps.setString(5, threat.getEvidence());
            ps.setDouble(6, threat.getConfidence());
            ps.setLong(7, threat.getTimestamp());
            ps.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            logger.error("Failed to save threat", e);
            try { connection.rollback(); } catch (SQLException re) { /* ignored */ }
        }
    }

    @Override
    public void close() {
        if (connection != null) {
            try {
                connection.close();
                logger.info("Database connection closed.");
            } catch (SQLException e) {
                logger.error("Error closing database connection", e);
            }
        }
    }
}
