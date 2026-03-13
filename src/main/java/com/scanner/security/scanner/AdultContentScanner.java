package com.scanner.security.scanner;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class AdultContentScanner {

    
    private static final List<String> ADULT_TLDS = List.of(
        ".xxx", ".adult", ".sex", ".porn"
    );

    
    private static final List<String> ADULT_DOMAIN_KEYWORDS = List.of(
        "porn", "xxx", "sex", "nude", "naked",
        "adult", "nsfw", "erotic", "hentai",
        "xvideos", "xhamster", "pornhub", "redtube",
        "youporn", "xnxx", "brazzers", "onlyfans",
        "chaturbate", "livejasmin", "cam4", "stripchat",
        "bangbros", "realitykings", "naughty", "slutty",
        "milf", "fetish", "escort", "stripper"
    );

    
    private static final List<String> ADULT_PATH_KEYWORDS = List.of(
        "/sex", "/porn", "/nude", "/naked", "/xxx",
        "/adult", "/nsfw", "/erotic", "/hentai",
        "/tags/sex", "/tags/porn", "/categories/adult",
        "/videos/sex", "/videos/porn"
    );

    
    private static final Pattern AGE_BYPASS =
        Pattern.compile(
            "(?i)(i.am.over.18|bypass.age|skip.age.verify"
            + "|enter.as.adult|age.gate.bypass)");

    public List<String> scanUrl(String url) {
        List<String> findings = new ArrayList<>();
        String lower = url.toLowerCase();

        
        ADULT_TLDS.stream()
            .filter(lower::contains)
            .forEach(tld -> findings.add(
                "Adult content TLD detected: " + tld));

        
        ADULT_DOMAIN_KEYWORDS.stream()
            .filter(lower::contains)
            .forEach(kw -> findings.add(
                "Adult content keyword detected in URL: " + kw));

        
        ADULT_PATH_KEYWORDS.stream()
            .filter(lower::contains)
            .forEach(path -> findings.add(
                "Adult content path detected in URL: " + path));

        
        if (AGE_BYPASS.matcher(url).find()) {
            findings.add(
                "Age verification bypass pattern detected");
        }

        return findings;
    }

    
    public List<String> scanContent(String content) {
        List<String> findings = new ArrayList<>();
        if (content == null || content.isBlank()) return findings;

        String lower = content.toLowerCase();

        
        long count = ADULT_DOMAIN_KEYWORDS.stream()
            .filter(lower::contains)
            .count();

        if (count >= 3) {
            findings.add(
                "Adult content detected in file — "
                + count + " explicit keywords found");
        } else if (count >= 1) {
            findings.add(
                "Possible adult content in file — "
                + count + " adult keyword(s) found");
        }

        return findings;
    }
}