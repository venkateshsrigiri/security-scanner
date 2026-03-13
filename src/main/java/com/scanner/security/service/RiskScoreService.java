package com.scanner.security.service;

import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class RiskScoreService {

    public int calculateScore(List<String> findings) {
        int score = 0;

        for (String finding : findings) {
            String f = finding.toLowerCase();

            
            if (f.contains("dangerous file type"))
                score += 30;

            else if (f.contains("malicious"))
                score += 25;

            else if (f.contains("embedded script"))
                score += 20;

            else if (f.contains("potential malicious"))
                score += 20;

            
            else if (f.contains("virustotal"))
                score += 20;

            
            else if (f.contains("brand impersonation"))
                score += 15;

            else if (f.contains("suspicious tld"))
                score += 15;

            else if (f.contains("ip-based url"))
                score += 15;

            else if (f.contains("phishing keyword"))
                score += 15;

            else if (f.contains("phishing"))
                score += 15;

            else if (f.contains("suspicious link"))
                score += 15;

            else if (f.contains("excessive subdomains"))
                score += 10;

            else if (f.contains("url shortener"))
                score += 10;

            else if (f.contains("suspicious webpage"))
                score += 10;

            
            else if (f.contains("credit card"))
                score += 10;

            else if (f.contains("sensitive email"))
                score += 10;

            else if (f.contains("suspicious words"))
                score += 10;

            
            else if (f.contains("non-https"))
                score += 5;

            else
                score += 5;
        }


        return Math.min(score, 100);
    }
}