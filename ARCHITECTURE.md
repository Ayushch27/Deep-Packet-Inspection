# System Architecture

## High-Level Pipeline

```text
                    ┌─────────────────────┐
                    │ Network Interface   │
                    │      / PCAP         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Packet Capture    │
                    │    / PCAP Reader    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Packet Preprocessor │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Packet Queue      │
                    │ BlockingQueue       │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┼─────────────┐
                 ▼             ▼             ▼
             Worker 1      Worker 2      Worker N
                 │             │             │
                 └─────────────┼─────────────┘
                               ▼
                    ┌─────────────────────┐
                    │   Flow Tracker      │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │      DPI Engine     │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
        HTTP Inspector    DNS Inspector    TLS Inspector
             │                 │                 │
             └─────────────────┼─────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Protocol/App        │
                    │ Classification      │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Threat Detection    │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Rule / Filter Engine│
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
           ALLOW              ALERT             BLOCK
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Logging / Database  │
                    │ / Statistics        │
                    └─────────────────────┘
```

## Module Responsibilities

1. **capture (`com.dpi.capture`)**
   - Handles PCAP file reading and live interface capturing via Pcap4J.
2. **parser (`com.dpi.parser`)**
   - Translates raw Pcap4J packets into our normalized internal `PacketInfo` model.
3. **model (`com.dpi.model`)**
   - Contains immutable data structures (`PacketInfo`, `Flow`, `ThreatResult`).
4. **flow (`com.dpi.flow`)**
   - Manages bidirectional connection tracking using concurrent data structures.
5. **dpi (`com.dpi.dpi`)**
   - The core Deep Packet Inspection engine orchestrating protocol inspectors.
6. **protocol (`com.dpi.protocol`)**
   - Contains individual protocol parsers/inspectors (HTTP, TLS, DNS).
7. **detection (`com.dpi.detection`)**
   - Threat detectors for Port Scans, SYN Floods, etc., and risk scoring.
8. **rules (`com.dpi.rules`)**
   - Evaluates parsed flows/packets against user-configured rules (ALLOW/BLOCK/ALERT).
9. **processing (`com.dpi.processing`)**
   - Manages the multithreaded worker pool and Producer-Consumer queue.
10. **statistics (`com.dpi.statistics`)**
    - High-performance, thread-safe counters (using `LongAdder`) for real-time reporting.
11. **storage (`com.dpi.storage`)**
    - SQLite persistence layer for logging alerts and flow metadata.
12. **export (`com.dpi.export`)**
    - Re-exports allowed or blocked packets to a new PCAP file.
13. **cli (`com.dpi.cli`)**
    - Handles command-line argument parsing and interactive console rendering.
14. **config (`com.dpi.config`)**
    - Parses configuration from properties and JSON files.
