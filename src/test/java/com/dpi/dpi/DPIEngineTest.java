package com.dpi.dpi;

import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class DPIEngineTest {

    private DPIEngine dpiEngine;

    @BeforeEach
    public void setUp() {
        dpiEngine = new DPIEngine();
    }

    @Test
    public void testHttpDetection() {
        String httpRequest = "GET /index.html HTTP/1.1\r\n" +
                "Host: test.example.com\r\n" +
                "User-Agent: Mozilla/5.0 DPI-Test\r\n" +
                "\r\n";

        byte[] payload = httpRequest.getBytes(StandardCharsets.UTF_8);

        PacketInfo packet = new PacketInfo.Builder()
                .timestamp(System.currentTimeMillis())
                .srcIp("192.168.1.5")
                .dstIp("93.184.216.34")
                .srcPort(51234)
                .dstPort(80)
                .protocol("TCP")
                .payload(payload)
                .payloadLength(payload.length)
                .packetLength(payload.length + 54)
                .build();

        Flow flow = new Flow("test-http-flow", "192.168.1.5", "93.184.216.34", 51234, 80, "TCP", packet.getTimestamp());

        dpiEngine.analyze(flow, packet);

        assertEquals("HTTP", flow.getApplicationProtocol());
        assertTrue(flow.getConfidence() >= 0.9);
        assertNotNull(flow.getHttpMetadata());
        assertEquals("GET", flow.getHttpMetadata().getMethod());
        assertEquals("/index.html", flow.getHttpMetadata().getUri());
        assertEquals("test.example.com", flow.getHttpMetadata().getHost());
        assertEquals("Mozilla/5.0 DPI-Test", flow.getHttpMetadata().getUserAgent());
    }

    @Test
    public void testDnsDetection() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Header
        out.write(new byte[] { 0x12, 0x34 }); // Transaction ID
        out.write(new byte[] { 0x01, 0x00 }); // Flags: Standard query
        out.write(new byte[] { 0x00, 0x01 }); // Questions: 1
        out.write(new byte[] { 0x00, 0x00 }); // Answer RRs: 0
        out.write(new byte[] { 0x00, 0x00 }); // Authority RRs: 0
        out.write(new byte[] { 0x00, 0x00 }); // Additional RRs: 0

        // QNAME: example.com
        out.write((byte) 7);
        out.write("example".getBytes(StandardCharsets.US_ASCII));
        out.write((byte) 3);
        out.write("com".getBytes(StandardCharsets.US_ASCII));
        out.write((byte) 0); // End of QNAME

        // QTYPE: A (0x0001)
        out.write(new byte[] { 0x00, 0x01 });
        // QCLASS: IN (0x0001)
        out.write(new byte[] { 0x00, 0x01 });

        byte[] payload = out.toByteArray();

        PacketInfo packet = new PacketInfo.Builder()
                .timestamp(System.currentTimeMillis())
                .srcIp("192.168.1.5")
                .dstIp("8.8.8.8")
                .srcPort(49152)
                .dstPort(53)
                .protocol("UDP")
                .payload(payload)
                .payloadLength(payload.length)
                .packetLength(payload.length + 42)
                .build();

        Flow flow = new Flow("test-dns-flow", "192.168.1.5", "8.8.8.8", 49152, 53, "UDP", packet.getTimestamp());

        dpiEngine.analyze(flow, packet);

        assertEquals("DNS", flow.getApplicationProtocol());
        assertTrue(flow.getConfidence() >= 0.9);
        assertNotNull(flow.getDnsMetadata());
        assertEquals("example.com", flow.getDnsMetadata().getQueryName());
        assertEquals("A", flow.getDnsMetadata().getQueryType());
    }

    @Test
    public void testTlsClientHelloWithSniDetection() throws IOException {
        ByteArrayOutputStream handshakeBody = new ByteArrayOutputStream();
        // Handshake Version: TLS 1.2 (0x03, 0x03)
        handshakeBody.write(new byte[] { 0x03, 0x03 });
        // Random: 32 bytes
        handshakeBody.write(new byte[32]);
        // Session ID Length: 0
        handshakeBody.write((byte) 0);
        // Cipher Suites Length: 2
        handshakeBody.write(new byte[] { 0x00, 0x02 });
        handshakeBody.write(new byte[] { (byte) 0xc0, 0x2f });
        // Compression Methods Length: 1, Method: 0
        handshakeBody.write((byte) 1);
        handshakeBody.write((byte) 0);

        // Extensions
        ByteArrayOutputStream extStream = new ByteArrayOutputStream();
        // SNI Extension (Type: 0x0000)
        String serverName = "secure.domain.com";
        byte[] nameBytes = serverName.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream sniData = new ByteArrayOutputStream();
        // Server Name List Length: 3 + nameBytes.length
        int listLen = 3 + nameBytes.length;
        sniData.write((byte) ((listLen >> 8) & 0xFF));
        sniData.write((byte) (listLen & 0xFF));
        // Server Name Type: host_name (0)
        sniData.write((byte) 0);
        // Server Name Length
        sniData.write((byte) ((nameBytes.length >> 8) & 0xFF));
        sniData.write((byte) (nameBytes.length & 0xFF));
        sniData.write(nameBytes);

        byte[] sniPayload = sniData.toByteArray();
        // Extension Type: 0x0000
        extStream.write(new byte[] { 0x00, 0x00 });
        // Extension Length
        extStream.write((byte) ((sniPayload.length >> 8) & 0xFF));
        extStream.write((byte) (sniPayload.length & 0xFF));
        extStream.write(sniPayload);

        byte[] allExt = extStream.toByteArray();
        // Extensions total length
        handshakeBody.write((byte) ((allExt.length >> 8) & 0xFF));
        handshakeBody.write((byte) (allExt.length & 0xFF));
        handshakeBody.write(allExt);

        byte[] hsData = handshakeBody.toByteArray();

        // TLS Record Header
        ByteArrayOutputStream recordStream = new ByteArrayOutputStream();
        recordStream.write((byte) 0x16); // Content Type: Handshake
        recordStream.write(new byte[] { 0x03, 0x01 }); // Record Version: TLS 1.0 (typical in ClientHello)
        int recordLen = 4 + hsData.length;
        recordStream.write((byte) ((recordLen >> 8) & 0xFF));
        recordStream.write((byte) (recordLen & 0xFF));

        // Handshake Header
        recordStream.write((byte) 0x01); // Handshake Type: Client Hello
        // Handshake Length: 3 bytes
        recordStream.write((byte) ((hsData.length >> 16) & 0xFF));
        recordStream.write((byte) ((hsData.length >> 8) & 0xFF));
        recordStream.write((byte) (hsData.length & 0xFF));
        recordStream.write(hsData);

        byte[] payload = recordStream.toByteArray();

        PacketInfo packet = new PacketInfo.Builder()
                .timestamp(System.currentTimeMillis())
                .srcIp("192.168.1.5")
                .dstIp("142.250.190.46")
                .srcPort(53210)
                .dstPort(443)
                .protocol("TCP")
                .payload(payload)
                .payloadLength(payload.length)
                .packetLength(payload.length + 54)
                .build();

        Flow flow = new Flow("test-tls-flow", "192.168.1.5", "142.250.190.46", 53210, 443, "TCP", packet.getTimestamp());

        dpiEngine.analyze(flow, packet);

        assertEquals("HTTPS/TLS", flow.getApplicationProtocol());
        assertTrue(flow.getConfidence() >= 0.9);
        assertNotNull(flow.getTlsMetadata());
        assertEquals("secure.domain.com", flow.getTlsMetadata().getSni());
    }

    @Test
    public void testPortBasedFallback() {
        PacketInfo packet = new PacketInfo.Builder()
                .timestamp(System.currentTimeMillis())
                .srcIp("192.168.1.5")
                .dstIp("10.0.0.1")
                .srcPort(51234)
                .dstPort(22)
                .protocol("TCP")
                .payload(new byte[0])
                .payloadLength(0)
                .packetLength(54)
                .build();

        Flow flow = new Flow("test-ssh-flow", "192.168.1.5", "10.0.0.1", 51234, 22, "TCP", packet.getTimestamp());

        dpiEngine.analyze(flow, packet);

        assertEquals("SSH", flow.getApplicationProtocol());
    }
}
