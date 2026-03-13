package com.scanner.security.scanner;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class UrlSafetyScanner {

    // Suspicious TLDs commonly used in attacks
    private static final List<String> BAD_TLDS = List.of(
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".xyz", ".top", ".click", ".loan",
        ".work", ".party", ".gdn", ".racing"
    );

    // URL shorteners hide the real destination
    private static final List<String> SHORTENERS = List.of(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
        "ow.ly", "is.gd", "buff.ly", "rebrand.ly"
    );

    // Brands commonly impersonated in phishing
    private static final List<String> IMPERSONATED = List.of(
        "paypal", "apple", "microsoft", "amazon",
        "netflix", "google", "facebook", "instagram",
        "whatsapp", "linkedin", "twitter", "bankofamerica",
        "chase", "wellsfargo", "hsbc", "barclays"
    );

    // Phishing action words
    private static final List<String> PHISHING_WORDS = List.of(
        "login", "verify", "bank", "secure",
        "update-password", "confirm", "account",
        "suspend", "unusual-activity", "validate",
        "signin", "authenticate", "recover"
    );

    // IP address URL — no domain name
    private static final Pattern IP_PATTERN =
        Pattern.compile("https?://(\\d{1,3}\\.){3}\\d{1,3}");

    // Excessive subdomains — e.g. login.verify.secure.paypal.fake.com
    private static final Pattern SUBDOMAIN_PATTERN =
        Pattern.compile("https?://([^/]+)");

    public List<String> scanUrl(String url) {
        List<String> findings = new ArrayList<>();
        String lower = url.toLowerCase();

        // ── 1. IP-based URL ────────────────────────────────────
        if (IP_PATTERN.matcher(url).find()) {
            findings.add(
                "IP-based URL detected — no domain name used");
        }

        // ── 2. Suspicious TLD ──────────────────────────────────
        BAD_TLDS.stream()
            .filter(tld -> lower.contains(tld))
            .forEach(tld -> findings.add(
                "Suspicious TLD detected: " + tld));

        // ── 3. URL shortener ───────────────────────────────────
        SHORTENERS.stream()
            .filter(s -> lower.contains(s))
            .forEach(s -> findings.add(
                "URL shortener detected: " + s
                + " — real destination is hidden"));

        // ── 4. Brand impersonation ─────────────────────────────
        IMPERSONATED.stream()
            .filter(brand -> lower.contains(brand))
            .forEach(brand -> findings.add(
                "Possible brand impersonation: "
                + brand + " found in URL"));

        // ── 5. Phishing keywords ───────────────────────────────
        PHISHING_WORDS.stream()
            .filter(word -> lower.contains(word))
            .forEach(word -> findings.add(
                "Phishing keyword detected in URL: " + word));

        // ── 6. Excessive subdomains ────────────────────────────
        var matcher = SUBDOMAIN_PATTERN.matcher(url);
        if (matcher.find()) {
            String host = matcher.group(1);
            long dots = host.chars()
                .filter(c -> c == '.').count();
            if (dots >= 3) {
                findings.add(
                    "Excessive subdomains detected ("
                    + dots + " levels) — possible spoofing");
            }
        }

        // ── 7. Encoded characters ──────────────────────────────
        if (lower.contains("%2f") || lower.contains("%40")
                || lower.contains("%00")) {
            findings.add(
                "Suspicious URL encoding detected "
                + "— possible filter bypass");
        }

        // ── 8. HTTPS check ─────────────────────────────────────
        if (url.startsWith("http://")) {
            findings.add(
                "Non-HTTPS URL — connection is not encrypted");
        }

        return findings;
    }
}