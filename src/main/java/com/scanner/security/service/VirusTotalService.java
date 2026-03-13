package com.scanner.security.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class VirusTotalService {

    @Value("${virustotal.api.key}")
    private String apiKey;

    private final HttpClient client = HttpClient.newHttpClient();

    public String checkUrl(String url) {
        try {
            // ── Step 1: Look up URL in VirusTotal ─────────────
            String encoded = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(url.getBytes());

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(
                    "https://www.virustotal.com/api/v3/urls/" + encoded))
                .header("x-apikey", apiKey)
                .GET()
                .build();

            HttpResponse<String> response = client.send(
                request, HttpResponse.BodyHandlers.ofString());

            String body = response.body();

            // ── Step 2: URL found in database — parse result ───
            if (response.statusCode() == 200) {

                int malicious  = extractStat(body, "malicious");
                int suspicious = extractStat(body, "suspicious");

                if (malicious > 0) {
                    return "VirusTotal: " + malicious
                        + " engine(s) flagged this URL as MALICIOUS";
                }
                if (suspicious > 0) {
                    return "VirusTotal: " + suspicious
                        + " engine(s) flagged this URL as SUSPICIOUS";
                }

                // URL is in database and is clean
                return "No external threat detected";

            // ── Step 3: URL not in database — submit it ────────
            } else if (response.statusCode() == 404) {
                submitUrl(url);
                // Do NOT add "submitted" as a finding
                // Just return clean — it will be analysed in background
                return "No external threat detected";

            } else {
                return "No external threat detected";
            }

        } catch (Exception e) {
            // Never crash the scan if VirusTotal is unreachable
            return "No external threat detected";
        }
    }

    // ── Submit a new URL to VirusTotal for background analysis ──
    // Does NOT return a finding — just queues it for future scans
    private void submitUrl(String url) {
        try {
            String formData = "url=" +
                java.net.URLEncoder.encode(
                    url, java.nio.charset.StandardCharsets.UTF_8);

            HttpRequest submitRequest = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/api/v3/urls"))
                .header("x-apikey", apiKey)
                .header("Content-Type",
                    "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formData))
                .build();

            client.send(submitRequest,
                HttpResponse.BodyHandlers.ofString());

        } catch (Exception e) {
            // Silently ignore — submission failure is not critical
        }
    }

    // ── Extract a number from VirusTotal JSON response ───────────
    // Looks for pattern like: "malicious": 5
    private int extractStat(String json, String key) {
        try {
            String search = "\"" + key + "\":";
            int idx = json.indexOf(search);
            if (idx == -1) return 0;

            int start = idx + search.length();

            // Skip whitespace
            while (start < json.length()
                    && json.charAt(start) == ' ') {
                start++;
            }

            int end = start;
            while (end < json.length()
                    && Character.isDigit(json.charAt(end))) {
                end++;
            }

            if (start == end) return 0;
            return Integer.parseInt(json.substring(start, end));

        } catch (Exception e) {
            return 0;
        }
    }
}
