# Java Deep Packet Inspection (DPI) Engine

A complete, production-quality Deep Packet Inspection, packet analysis, traffic classification, and network security monitoring system implemented in Java. 

## Objectives
* Read packets from PCAP files or capture live network traffic.
* Parse Ethernet, IP (v4/v6), TCP, UDP, and ICMP protocols.
* Track network flows and perform Deep Packet Inspection (DPI) to identify application-layer protocols (HTTP, TLS, DNS, etc.).
* Detect suspicious traffic such as port scans and SYN floods.
* Apply configurable rule-based filtering (allow/block/alert).
* Process packets concurrently with a scalable producer-consumer architecture.

## Technology Stack
* **Java 17**
* **Maven** for dependency management and build
* **Pcap4J** for packet capture and low-level parsing
* **SQLite** for persistence of results
* **SLF4J + Logback** for logging
* **JUnit 5** for testing

## How to Build & Run

### Prerequisites
* **Java 17+**
* **Npcap (Windows)** or **libpcap (Linux/macOS)** installed with WinPcap-compatible mode.

### Compile and Package
```bash
# Using system maven or the included portable maven
.\maven\apache-maven-3.9.5\bin\mvn.cmd clean package
```

### Run Unit Tests
```bash
.\maven\apache-maven-3.9.5\bin\mvn.cmd test
```

### CLI Options & Usage Examples

```bash
# 1. List all available live network interfaces
java -jar target/deep-packet-inspection-1.0-SNAPSHOT-jar-with-dependencies.jar --list-interfaces

# 2. Inspect an offline PCAP file
java -jar target/deep-packet-inspection-1.0-SNAPSHOT-jar-with-dependencies.jar --pcap pcaps/input/sample.pcap

# 3. Inspect PCAP and export allowed/filtered packets to a new PCAP
java -jar target/deep-packet-inspection-1.0-SNAPSHOT-jar-with-dependencies.jar --pcap pcaps/input/sample.pcap --output pcaps/output/exported.pcap

# 4. Filter traffic by protocol and port
java -jar target/deep-packet-inspection-1.0-SNAPSHOT-jar-with-dependencies.jar --pcap pcaps/input/sample.pcap --filter "protocol=TCP" --filter "port=443"

# 5. Live network capture (replace with interface name from --list-interfaces)
java -jar target/deep-packet-inspection-1.0-SNAPSHOT-jar-with-dependencies.jar --interface "\Device\NPF_Loopback"
```

## Features Implemented
* **Flow Tracking**: Bidirectional 5-tuple connection aggregation with automatic expiration cleanup.
* **Deep Packet Inspection (DPI)**: 
  * HTTP Header Parsing (Method, URI, Host, User-Agent, Status Code)
  * TLS / HTTPS Handshake Inspection (ClientHello SNI hostname & ALPN extraction)
  * DNS Query Inspection (Transaction ID, QNAME, QTYPE resolution)
  * Fallback port-based classification.
* **Threat Detection**:
  * Port Scan detection (unique ports per time window)
  * Volumetric Flood detection (TCP SYN flood, ICMP flood)
* **Rule Engine**:
  * Block/allow lists by IP and domain (`config/rules.json`)
* **PCAP Exporter**:
  * Selective re-exporting of allowed packets (`--output`)
* **Persistence & Reporting**:
  * SQLite database (`data/dpi.db`) storing flows and alerts
  * Real-time CLI Dashboard with throughput metrics, protocol breakdown, and recent alerts
  * Graceful JVM shutdown hook handling `Ctrl+C` seamlessly.
