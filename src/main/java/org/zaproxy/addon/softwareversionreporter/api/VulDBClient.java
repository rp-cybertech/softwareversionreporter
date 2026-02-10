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
import org.zaproxy.addon.softwareversionreporter.VulnerabilityMappers;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

/**
 * VulDB API client.
 * Documentation: https://vuldb.com/?api
 * 
 * VulDB API format (form-encoded):
 * POST https://vuldb.com/?api
 * apikey=your_api_key&search=apache+struts+2.3
 */
public class VulDBClient {
    private static final Logger LOGGER = LogManager.getLogger(VulDBClient.class);
    private static final String API_URL = "https://vuldb.com/?api";
    private static final long RATE_LIMIT_DELAY_MS = 1000; // 1 second between requests
    private static long lastRequestTime = 0;
    private final String apiKey;
    private final HttpClient http;
    private final ObjectMapper mapper;

    public VulDBClient(String apiKey) {
        this.apiKey = apiKey;
        this.mapper = new ObjectMapper();
        this.http =
                HttpClient.newBuilder()
                        .proxy(ProxySelector.getDefault())
                        .connectTimeout(Duration.ofSeconds(20))
                        .build();
    }

    public EnrichmentResult query(String software, String version, String vendor, String product)
            throws Exception {
        
        // Validate API key
        if (apiKey == null || apiKey.isBlank()) {
            LOGGER.warn("SVR:VulDB API key is not configured");
            EnrichmentResult emptyResult = new EnrichmentResult(software, version);
            emptyResult.setSource("VulDB");
            return emptyResult;
        }
        
        // Rate limiting - avoid 429 errors
        synchronized (VulDBClient.class) {
            long now = System.currentTimeMillis();
            long timeSinceLastRequest = now - lastRequestTime;
            if (timeSinceLastRequest < RATE_LIMIT_DELAY_MS) {
                long sleepTime = RATE_LIMIT_DELAY_MS - timeSinceLastRequest;
                LOGGER.debug("SVR:VulDB rate limiting - sleeping {} ms", sleepTime);
                Thread.sleep(sleepTime);
            }
            lastRequestTime = System.currentTimeMillis();
        }
        
        // Build search query using product name
        String searchProduct = product != null && !product.isBlank() ? product : software;
        String searchVendor = vendor != null && !vendor.isBlank() ? vendor : null;
        
        StringBuilder searchQuery = new StringBuilder();
        if (searchVendor != null && !searchVendor.equalsIgnoreCase(searchProduct)) {
            searchQuery.append(searchVendor).append(" ");
        }
        searchQuery.append(searchProduct);
        if (version != null && !version.isBlank()) {
            searchQuery.append(" ").append(version);
        }

        // Build form-encoded request body
        String requestBody = String.format("apikey=%s&search=%s",
            URLEncoder.encode(apiKey, StandardCharsets.UTF_8),
            URLEncoder.encode(searchQuery.toString(), StandardCharsets.UTF_8)
        );
        
        LOGGER.debug("SVR:VulDB request body: {}", requestBody);

        HttpRequest request =
                HttpRequest.newBuilder(URI.create(API_URL))
                        .timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Accept", "application/json")
                        .header("User-Agent", "ZAP-SoftwareVersionReporter/1.0")
                        .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                        .build();

        long t0 = System.nanoTime();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        int code = response.statusCode();
        String body = response.body() == null ? "" : response.body();
        int bytes = body.getBytes(StandardCharsets.UTF_8).length;
        long ms = Math.round((System.nanoTime() - t0) / 1_000_000.0);

        EnrichmentResult result = new EnrichmentResult(software, version);
        result.setSource("VulDB");
        
        if (code != 200) {
            LOGGER.warn("SVR:VulDB API error code={} ms={} body={}", code, ms, 
                body.length() > 500 ? body.substring(0, 500) + "..." : body);
            return result;
        }

        int count = 0;
        try {
            JsonNode root = mapper.readTree(body);
            
            // Log response structure for debugging
            LOGGER.debug("SVR:VulDB response keys: {}", root.fieldNames());
            
            // Check for API errors
            if (root.has("error") && !root.path("error").isNull()) {
                String errorMsg = root.path("error").asText();
                LOGGER.warn("SVR:VulDB API returned error: {}", errorMsg);
                return result;
            }
            
            // Parse vulnerabilities - try different response paths
            JsonNode results = null;
            
            if (root.has("result") && root.path("result").isArray()) {
                results = root.path("result");
                LOGGER.debug("SVR:VulDB found results in 'result' array");
            } else if (root.has("data") && root.path("data").isArray()) {
                results = root.path("data");
                LOGGER.debug("SVR:VulDB found results in 'data' array");
            } else if (root.has("vulnerabilities") && root.path("vulnerabilities").isArray()) {
                results = root.path("vulnerabilities");
                LOGGER.debug("SVR:VulDB found results in 'vulnerabilities' array");
            } else if (root.isArray()) {
                // Root is an array
                results = root;
                LOGGER.debug("SVR:VulDB response is root array");
            }
            
            if (results != null && results.isArray()) {
                count = results.size();
                LOGGER.debug("SVR:VulDB array size: {}", count);
                
                for (JsonNode item : results) {
                    LOGGER.debug("SVR:VulDB processing item: {}", item.toString().substring(0, Math.min(200, item.toString().length())));
                    var vulnInfo = VulnerabilityMappers.mapVuldbEntry(item);
                    if (vulnInfo != null && vulnInfo.getCveId() != null && !vulnInfo.getCveId().isEmpty()) {
                        result.getVulnerabilities().add(vulnInfo);
                    }
                }
            } else {
                LOGGER.debug("SVR:VulDB no results array found. Response preview: {}", 
                    body.length() > 300 ? body.substring(0, 300) + "..." : body);
            }
            
            LOGGER.info(
                    "SVR:VulDB status={} items={} parsed={} ms={} bytes={} vendor={} product={}",
                    code,
                    count,
                    result.getVulnerabilities().size(),
                    ms,
                    bytes,
                    searchVendor != null ? searchVendor : "null",
                    searchProduct);
                    
        } catch (Exception parseEx) {
            LOGGER.warn("SVR:VulDB parse error code={} bytes={} ms={} error={}", 
                code, bytes, ms, parseEx.getMessage());
            LOGGER.debug("SVR:VulDB response body: {}", body);
        }
        
        return result;
    }
}
