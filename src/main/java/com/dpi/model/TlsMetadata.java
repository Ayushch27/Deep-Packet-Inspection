package com.dpi.model;

public class TlsMetadata {
    private String tlsVersion;
    private String sni;
    private String alpn;

    public String getTlsVersion() { return tlsVersion; }
    public void setTlsVersion(String tlsVersion) { this.tlsVersion = tlsVersion; }

    public String getSni() { return sni; }
    public void setSni(String sni) { this.sni = sni; }

    public String getAlpn() { return alpn; }
    public void setAlpn(String alpn) { this.alpn = alpn; }

    @Override
    public String toString() {
        return "TLS [Version: " + tlsVersion + ", SNI: " + sni + ", ALPN: " + alpn + "]";
    }
}
