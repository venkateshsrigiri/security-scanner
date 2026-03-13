package com.scanner.security.dto;

public class UrlRequestDTO {

    // Matches what UrlScanner.jsx sends:
    // axios.post("/scan/url", { url: "https://..." })
    private String url;

    public UrlRequestDTO() {}

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
}