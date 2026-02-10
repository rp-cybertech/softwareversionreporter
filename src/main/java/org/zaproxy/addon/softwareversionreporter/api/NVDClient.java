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
import org.zaproxy.addon.softwareversionreporter.util.CpeUtil;

public class NVDClient {
    private static final Logger LOGGER = LogManager.getLogger(NVDClient.class);
    
    // Constants for API configuration
    private static final int RESULTS_PER_PAGE = 2000;
    private static final int MAX_PAGES = 10;
    private static final int CONNECT_TIMEOUT_SECONDS = 20;
    private static final int REQUEST_TIMEOUT_SECONDS = 30;
    private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final String USER_AGENT = "ZAP-SoftwareVersionReporter/1.0";
    private static final String VALID_HOST_SUFFIX = "nist.gov";
    
    private final String apiKey;
    private final HttpClient http;

    public NVDClient(String apiKey) {
        this.apiKey = apiKey;
        this.http =
                HttpClient.newBuilder()
                        .proxy(ProxySelector.getDefault())
                        .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
                        .build();
    }

    public EnrichmentResult queryByCpe(String software, String version, String cpe)
            throws Exception {
        // Use virtualMatchString instead of cpeName for broader matching
        // This finds all CVEs related to the product, then we filter by version
        String base = BASE_URL;
        CpeUtil.Parts parts = CpeUtil.parse(cpe);

        // Validate vendor and product
        String vendor = parts.vendor;
        String product = parts.product;
        if (vendor == null
                || vendor.isBlank()
                || vendor.equals("*")
                || product == null
                || product.isBlank()
                || product.equals("*")) {
            LOGGER.warn(
                    "SVR:NVD invalid vendor/product in CPE: {} (vendor={}, product={})",
                    cpe,
                    vendor,
                    product);
            // Fall back to building CPE from software name
            vendor = software.toLowerCase().replaceAll("[^a-z0-9_]", "_");
            product = software.toLowerCase().replaceAll("[^a-z0-9_]", "_");
        }

        String matchString = CpeUtil.buildProductOnly(vendor, product);
        String qsBase =
                "virtualMatchString=" + URLEncoder.encode(matchString, StandardCharsets.UTF_8);
        qsBase += "&resultsPerPage=" + RESULTS_PER_PAGE;

        EnrichmentResult er = new EnrichmentResult(software, version);
        er.setSource("NVD");
        er.setCpe(cpe);

        int total = 0;
        int matched = 0;
        int startIndex = 0;
        int maxPages = MAX_PAGES;
        int pagesFetched = 0;
        ObjectMapper om = new ObjectMapper();

        while (pagesFetched < maxPages) {
            String qs = qsBase + "&startIndex=" + startIndex;
            String fullUrl = base + "?" + qs;
            
            // Validate and sanitize the URL to prevent injection
            try {
                URI uri = URI.create(fullUrl);
                if (!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) {
                    LOGGER.error("SVR:NVD Invalid URL scheme: {}", fullUrl);
                    break;
                }
                // Additional validation to prevent SSRF
                if (uri.getHost() == null || !uri.getHost().endsWith(VALID_HOST_SUFFIX)) {
                    LOGGER.error("SVR:NVD Invalid host for security: {}", uri.getHost());
                    break;
                }
            } catch (Exception e) {
                LOGGER.error("SVR:NVD Invalid URL format: {}", fullUrl, e);
                break;
            }
            
            URI uri = URI.create(fullUrl);

            long t0 = System.nanoTime();
            HttpRequest.Builder rb =
                    HttpRequest.newBuilder(uri)
                            .timeout(Duration.ofSeconds(REQUEST_TIMEOUT_SECONDS))
                            .header("Accept", "application/json")
                            .header("User-Agent", USER_AGENT)
                            .GET();
            if (apiKey != null && !apiKey.isBlank()) {
                rb.header("apiKey", apiKey);
            }
            HttpResponse<String> resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofString());
            int code = resp.statusCode();
            String body = resp.body() == null ? "" : resp.body();
            int bytes = body.getBytes(StandardCharsets.UTF_8).length;
            long ms = Math.round((System.nanoTime() - t0) / 1_000_000.0);

            JsonNode root = null;
            try {
                root = om.readTree(body);
                int pageTotal = root.path("totalResults").asInt(0);
                if (pagesFetched == 0) {
                    total = pageTotal;
                }

                if (root.path("vulnerabilities").isArray()) {
                    for (JsonNode v : root.path("vulnerabilities")) {
                        JsonNode cve = v.path("cve");
                        if (cve.isMissingNode()) continue;

                        if (isVersionAffected(cve, version)) {
                            er.getVulnerabilities().add(VulnerabilityMappers.mapNvdCve(cve));
                            matched++;
                        }
                    }
                }

                LOGGER.info(
                        "SVR:NVD page={} status={} total={} matched={} ms={} bytes={} url={}",
                        pagesFetched,
                        code,
                        pageTotal,
                        matched,
                        ms,
                        bytes,
                        uri.toString());

                // Check if we need to fetch more pages
                int resultsPerPage = root.path("resultsPerPage").asInt(2000);
                if (startIndex + resultsPerPage >= pageTotal) {
                    break; // All results fetched
                }
                startIndex += resultsPerPage;

            } catch (com.fasterxml.jackson.core.JsonProcessingException jsonEx) {
                LOGGER.warn(
                        "SVR:NVD JSON parse error page={} code={} bytes={} ms={} url={}",
                        pagesFetched,
                        code,
                        bytes,
                        ms,
                        uri.toString());
                break;
            } catch (Exception parseEx) {
                LOGGER.warn(
                        "SVR:NVD unexpected error page={} code={} bytes={} ms={} url={}",
                        pagesFetched,
                        code,
                        bytes,
                        ms,
                        uri.toString(), parseEx);
                break;
            }

            pagesFetched++;

            // Rate limiting - be nice to NVD API
            if (pagesFetched < maxPages && startIndex < total) {
                try {
                    Thread.sleep(apiKey != null && !apiKey.isBlank() ? 100 : 6000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        LOGGER.info("SVR:NVD complete pages={} total={} matched={}", pagesFetched, total, matched);
        return er;
    }

    private boolean isVersionAffected(JsonNode cve, String detectedVersion) {
        if (detectedVersion == null || detectedVersion.isBlank()) return true;

        JsonNode configurations = cve.path("configurations");
        if (!configurations.isArray() || configurations.size() == 0) return true;

        // Check each configuration
        for (JsonNode config : configurations) {
            JsonNode nodes = config.path("nodes");
            if (!nodes.isArray()) continue;

            for (JsonNode node : nodes) {
                JsonNode cpeMatch = node.path("cpeMatch");
                if (!cpeMatch.isArray()) continue;

                for (JsonNode match : cpeMatch) {
                    if (!match.path("vulnerable").asBoolean(true)) continue;

                    String criteria = match.path("criteria").asText("");
                    String verStart = match.path("versionStartIncluding").asText(null);
                    String verStartExcl = match.path("versionStartExcluding").asText(null);
                    String verEnd = match.path("versionEndIncluding").asText(null);
                    String verEndExcl = match.path("versionEndExcluding").asText(null);

                    // If no version constraints specified, assume it applies
                    if (verStart == null
                            && verStartExcl == null
                            && verEnd == null
                            && verEndExcl == null) {
                        // Check exact version match in criteria
                        String cpeVer =
                                org.zaproxy.addon.softwareversionreporter.util.VersionUtil
                                        .extractVersionFromCpe(criteria);
                        if (cpeVer == null || cpeVer.equals("*") || cpeVer.isBlank()) return true;
                        if (cpeVer.equals(detectedVersion)) return true;
                        continue;
                    }

                    // Check version range
                    boolean affected = true;

                    // Check start version
                    if (verStart != null && !verStart.isBlank()) {
                        if (org.zaproxy.addon.softwareversionreporter.util.VersionUtil
                                        .compareVersions(detectedVersion, verStart)
                                < 0) {
                            affected = false;
                        }
                    } else if (verStartExcl != null && !verStartExcl.isBlank()) {
                        if (org.zaproxy.addon.softwareversionreporter.util.VersionUtil
                                        .compareVersions(detectedVersion, verStartExcl)
                                <= 0) {
                            affected = false;
                        }
                    }

                    // Check end version
                    if (affected && verEnd != null && !verEnd.isBlank()) {
                        if (org.zaproxy.addon.softwareversionreporter.util.VersionUtil
                                        .compareVersions(detectedVersion, verEnd)
                                > 0) {
                            affected = false;
                        }
                    } else if (affected && verEndExcl != null && !verEndExcl.isBlank()) {
                        if (org.zaproxy.addon.softwareversionreporter.util.VersionUtil
                                        .compareVersions(detectedVersion, verEndExcl)
                                >= 0) {
                            affected = false;
                        }
                    }

                    if (affected) return true;
                }
            }
        }

        return false;
    }
}
