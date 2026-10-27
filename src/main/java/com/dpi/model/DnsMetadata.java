package com.dpi.model;

public class DnsMetadata {
    private int transactionId;
    private String queryName;
    private String queryType;
    private int responseCode;
    private int answerCount;

    public int getTransactionId() { return transactionId; }
    public void setTransactionId(int transactionId) { this.transactionId = transactionId; }

    public String getQueryName() { return queryName; }
    public void setQueryName(String queryName) { this.queryName = queryName; }

    public String getQueryType() { return queryType; }
    public void setQueryType(String queryType) { this.queryType = queryType; }

    public int getResponseCode() { return responseCode; }
    public void setResponseCode(int responseCode) { this.responseCode = responseCode; }

    public int getAnswerCount() { return answerCount; }
    public void setAnswerCount(int answerCount) { this.answerCount = answerCount; }

    @Override
    public String toString() {
        return "DNS [Query: " + queryName + " (" + queryType + "), RCode: " + responseCode + ", Answers: " + answerCount + "]";
    }
}
