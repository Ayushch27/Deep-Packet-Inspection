package com.dpi.model;

public class HttpMetadata {
    private String method;
    private String uri;
    private String host;
    private String userAgent;
    private Integer statusCode;
    private String contentType;

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUri() { return uri; }
    public void setUri(String uri) { this.uri = uri; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public Integer getStatusCode() { return statusCode; }
    public void setStatusCode(Integer statusCode) { this.statusCode = statusCode; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }

    @Override
    public String toString() {
        return "HTTP [" + (method != null ? method + " " + uri : "Status: " + statusCode) + ", Host: " + host + "]";
    }
}
