/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.softwareversionreporter.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

/**
 * Vulners API client using the Lucene search API (GET request).
 * https://vulners.com/help
 */
public class VulnersClient {
    private static final Logger LOGGER = LogManager.getLogger(VulnersClient.class);
    private static final String API_URL = "https://vulners.com/api/v3/search/lucene/";
    private static final long RATE_LIMIT_DELAY_MS = 500; // 500ms between requests
    private static long lastRequestTime = 0;
    private final String apiKey;
    private final HttpClient http;
    private final ObjectMapper mapper;

    public VulnersClient(String apiKey) {
        this.apiKey = apiKey;
        this.mapper = new ObjectMapper();
        this.http =
                HttpClient.newBuilder()
                        .proxy(ProxySelector.getDefault())
                        .connectTimeout(Duration.ofSeconds(20))
                        .build();
    }

    public EnrichmentResult queryByProduct(
            String software, String version, String vendor, String product) throws Exception {
        
        // Rate limiting
        synchronized (VulnersClient.class) {
            long now = System.currentTimeMillis();
            long timeSinceLastRequest = now - lastRequestTime;
            if (timeSinceLastRequest < RATE_LIMIT_DELAY_MS) {
                long sleepTime = RATE_LIMIT_DELAY_MS - timeSinceLastRequest;
                LOGGER.debug("SVR:Vulners rate limiting - sleeping {} ms", sleepTime);
                Thread.sleep(sleepTime);
            }
            lastRequestTime = System.currentTimeMillis();
        }
        
        // Build query string
        StringBuilder queryBuilder = new StringBuilder();
        
        // Add software/product to query
        String searchTerm = product != null && !product.isBlank() ? product : software;
        if (searchTerm != null && !searchTerm.isBlank()) {
            queryBuilder.append(searchTerm);
        }
        
        // Add version if available
        if (version != null && !version.isBlank()) {
            if (queryBuilder.length() > 0) {
                queryBuilder.append(" ");
            }
            queryBuilder.append(version);
        }

        String query = queryBuilder.toString();
        
        // Build URL with query parameters
        StringBuilder urlBuilder = new StringBuilder(API_URL);
        urlBuilder.append("?query=").append(URLEncoder.encode(query, StandardCharsets.UTF_8));
        urlBuilder.append("&skip=0");
        urlBuilder.append("&size=50");

        String url = urlBuilder.toString();
        
        LOGGER.debug("SVR:Vulners request URL: {}", url);

        HttpRequest.Builder requestBuilder =
                HttpRequest.newBuilder(URI.create(url))
                        .timeout(Duration.ofSeconds(30))
                        .header("Accept", "application/json")
                        .header("User-Agent", "ZAP-SoftwareVersionReporter/1.0")
                        .GET();
        
        // Add API key if available
        if (apiKey != null && !apiKey.isBlank()) {
            requestBuilder.header("X-Api-Key", apiKey);
        }

        long t0 = System.nanoTime();
        HttpResponse<String> response = http.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        int code = response.statusCode();
        String body = response.body() == null ? "" : response.body();
        int bytes = body.getBytes(StandardCharsets.UTF_8).length;
        long ms = Math.round((System.nanoTime() - t0) / 1_000_000.0);

        EnrichmentResult result = new EnrichmentResult(software, version);
        result.setSource("Vulners");
        
        if (code != 200) {
            LOGGER.warn("SVR:Vulners API error code={} ms={} body={}", code, ms,
                body.length() > 500 ? body.substring(0, 500) + "..." : body);
            return result;
        }

        int count = 0;
        try {
            JsonNode root = mapper.readTree(body);
            
            // Log response structure for debugging
            LOGGER.debug("SVR:Vulners response keys: {}", root.fieldNames());
            
            // Check result status
            String resultStatus = root.path("result").asText("");
            if (!"OK".equalsIgnoreCase(resultStatus)) {
                LOGGER.warn("SVR:Vulners API returned non-OK result: {}", resultStatus);
                return result;
            }
            
            // Parse vulnerabilities from data.search array
            JsonNode searchResults = root.path("data").path("search");
            if (searchResults.isArray()) {
                count = searchResults.size();
                LOGGER.debug("SVR:Vulners found {} items in data.search", count);
                
                for (JsonNode item : searchResults) {
                    var vulnInfo = org.zaproxy.addon.softwareversionreporter.VulnerabilityMappers
                            .mapVulnersItem(item);
                    if (vulnInfo != null && vulnInfo.getCveId() != null && !vulnInfo.getCveId().isEmpty()) {
                        result.getVulnerabilities().add(vulnInfo);
                    }
                }
            } else {
                LOGGER.debug("SVR:Vulners no data.search array found. Response preview: {}",
                    body.length() > 300 ? body.substring(0, 300) + "..." : body);
            }
            
            LOGGER.info(
                    "SVR:Vulners status={} items={} parsed={} ms={} bytes={} query={}",
                    code,
                    count,
                    result.getVulnerabilities().size(),
                    ms,
                    bytes,
                    query);
                    
        } catch (Exception parseEx) {
            LOGGER.warn("SVR:Vulners parse error code={} bytes={} ms={} error={}", 
                code, bytes, ms, parseEx.getMessage());
            LOGGER.debug("SVR:Vulners response body: {}", body);
        }
        
        return result;
    }
}
