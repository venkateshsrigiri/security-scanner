package com.scanner.security.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

import org.springframework.stereotype.Service;

@Service
public class WebContentFetcher {

    public String fetchContent(String urlString){
        StringBuilder content = new StringBuilder();
        try{
            URL url = java.net.URI.create(urlString).toURL();
            BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
            String line;
            while((line  = reader.readLine())!=null){
                content.append(line);
            }
            reader.close();

        }catch(Exception e){
            return "";
        }
        return content.toString();

    }


    
}
