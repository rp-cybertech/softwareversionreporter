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
package org.zaproxy.addon.softwareversionreporter;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.softwareversionreporter.DetectionRuleLoader.DetectionRule;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult.VulnerabilityInfo;
import org.zaproxy.addon.softwareversionreporter.util.SmartReportFormatter;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class SoftwareVersionReporterPassiveScanner extends PluginPassiveScanner {
    private static final Logger LOGGER =
            LogManager.getLogger(SoftwareVersionReporterPassiveScanner.class);
    private final Set<String> raisedOnce = new HashSet<>();

    @Override
    public int getPluginId() {
        return 40050;
    }

    @Override
    public String getName() {
        return "Software Version Reporter";
    }

    @Override
    public boolean appliesToHistoryType(int historyType) {
        return true;
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {}

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        String uri = msg.getRequestHeader().getURI().toString();
        LOGGER.debug("SVR pscan start uri={}", uri);
        try {
            ExtensionSoftwareVersionReporter ext = ExtensionSoftwareVersionReporter.getInstance();
            if (ext == null) {
                LOGGER.warn("SVR extension instance is null");
                return;
            }

            List<DetectionRule> rules = ext.getDetectionRules();
            if (rules == null || rules.isEmpty()) {
                LOGGER.warn("SVR no detection rules loaded");
                return;
            }

            HttpHeader headers = msg.getResponseHeader();
            String body = msg.getResponseBody().toString();

            for (DetectionRule rule : rules) {
                String field = rule.getType();
                String target = "body".equalsIgnoreCase(field) ? body : headers.getHeader(field);
                if (target == null || target.isBlank()) continue;

                Pattern p = Pattern.compile(rule.getPattern(), Pattern.CASE_INSENSITIVE);
                Matcher m = p.matcher(target);
                if (!m.find()) continue;

                String software = rule.getSoftware();
                String version = (m.groupCount() >= 1) ? m.group(1) : null;
                String vendor = rule.getCpeVendor();
                String product = rule.getCpeProduct();

                boolean enrichWhenNoVersion = ext.getParam().isEnrichWhenNoVersion();
                if (software == null || software.isBlank()) continue;
                if ((version == null || version.isBlank()) && !enrichWhenNoVersion) continue;

                LOGGER.info(
                        "SVR match software={} version={} field={} uri={}",
                        software,
                        version,
                        field,
                        uri);
                raiseSoftwareAlert(msg, vendor, product, software, version, field + ": " + target);
            }
        } catch (Exception e) {
            LOGGER.warn("SVR pscan error uri={}", uri, e);
        }
    }

    private void raiseSoftwareAlert(
            HttpMessage msg,
            String vendor,
            String product,
            String software,
            String version,
            String evidence) {
        String uri = msg.getRequestHeader().getURI().toString();
        String key = uri + "|" + software + "|" + (version == null ? "" : version);
        if (!raisedOnce.add(key)) return;

        EnrichmentResult er = null;
        try {
            er =
                    ExtensionSoftwareVersionReporter.getInstance()
                            .getEnrichmentService()
                            .query(software, version, vendor, product);
        } catch (Exception e) {
            LOGGER.info("SVR enrichment exception software={} version={}", software, version, e);
        }

        boolean has = er != null && er.hasVulnerabilities();

        // Get max severity from API response - no hardcoded calculations
        int risk = Alert.RISK_LOW; // Default when no vulns found
        if (has) {
            int maxRisk = Alert.RISK_LOW;
            for (VulnerabilityInfo v : er.getVulnerabilities()) {
                int vulnRisk = severityToRisk(v.getSeverity());
                if (vulnRisk > maxRisk) {
                    maxRisk = vulnRisk;
                }
            }
            risk = maxRisk;
        }

        if (has) {
            SmartReportFormatter.Report rep =
                    SmartReportFormatter.build(er.getSource(), software, version, er);
            LOGGER.info(
                    "SVR alert.added name='{}' risk={} items={} uri={}",
                    rep.title,
                    risk,
                    er.getVulnerabilities().size(),
                    uri);
            newAlert()
                    .setRisk(risk)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setName(rep.title)
                    .setDescription(rep.description)
                    .setSolution(rep.solution)
                    .setReference(rep.references)
                    .setOtherInfo("Tags: " + rep.tags)
                    .setEvidence(trim(evidence))
                    .setUri(uri)
                    .setMessage(msg)
                    .raise();
        } else {
            String sv = software + (version == null || version.isBlank() ? "" : " " + version);
            LOGGER.info(
                    "SVR alert.added name='Software Version Detected: {}' risk={} uri={}",
                    sv,
                    Alert.RISK_INFO,
                    uri);
            newAlert()
                    .setRisk(Alert.RISK_INFO)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setName("Software Version Detected: " + sv)
                    .setDescription("Detected software: " + sv)
                    .setSolution("Upgrade " + sv + " to the latest version.")
                    .setEvidence(trim(evidence))
                    .setUri(uri)
                    .setMessage(msg)
                    .raise();
        }
    }

    private static String trim(String s) {
        if (s == null) return "";
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() > 256 ? t.substring(0, 256) + "…" : t;
    }

    /**
     * Convert API severity string to ZAP Alert risk level. Uses API-provided severity directly
     * without hardcoded thresholds.
     */
    private static int severityToRisk(String severity) {
        if (severity == null || severity.isBlank()) {
            return Alert.RISK_LOW;
        }
        String s = severity.toUpperCase().trim();
        return switch (s) {
            case "CRITICAL" -> Alert.RISK_HIGH;
            case "HIGH" -> Alert.RISK_HIGH;
            case "MEDIUM" -> Alert.RISK_MEDIUM;
            case "LOW" -> Alert.RISK_LOW;
            case "INFO", "INFORMATIONAL" -> Alert.RISK_INFO;
            default -> Alert.RISK_LOW;
        };
    }
}
