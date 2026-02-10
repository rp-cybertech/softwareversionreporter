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
package org.zaproxy.addon.softwareversionreporter.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult.VulnerabilityInfo;

public final class SmartReportFormatter {
    // Constants for report generation
    private static final int MAX_LINES = 200;
    private static final int MAX_DESCRIPTION_LENGTH = 200;
    private static final String SEPARATOR_LINE = "-".repeat(80);

    private SmartReportFormatter() {}

    public static Report build(
            String provider, String software, String version, EnrichmentResult er) {
        List<VulnerabilityInfo> all;
        if (er != null && er.getVulnerabilities() != null) {
            all = er.getVulnerabilities();
        } else {
            all = List.of();
        }
        // Use LinkedHashMap to maintain order while providing O(1) lookups
        Map<String, VulnerabilityInfo> uniq = new LinkedHashMap<>();
        Set<String> seenKeys = new HashSet<>(); // For faster O(1) existence checks
        
        for (VulnerabilityInfo v : all) {
            if (isBlank(v.getTitle())
                    && isBlank(v.getCveId())
                    && isBlank(v.getShortDescription())
                    && isBlank(v.getDescription())) continue;
            String key = keyFor(v);
            
            // Use HashSet for faster existence check, then LinkedHashMap to maintain order
            if (!seenKeys.contains(key)) {
                seenKeys.add(key);
                uniq.put(key, v);
                if (uniq.size() >= MAX_LINES) break;
            }
        }
        List<VulnerabilityInfo> list = new ArrayList<>(uniq.values());

        String sv =
                isBlank(version)
                        ? nz(software, "software")
                        : (nz(software, "software") + " " + version);

        String title;
        StringBuilder desc = new StringBuilder();

        if (list.size() == 1) {
            // Single vulnerability - Nessus style
            VulnerabilityInfo v = list.get(0);
            String cve = nz(v.getCveId(), "");
            String severity = getSeverityLabel(v);

            if (!cve.isBlank()) {
                title = sv + " is vulnerable to " + cve;
            } else {
                title = sv + " - " + nz(v.getTitle(), "Vulnerability");
            }

            desc.append("The detected version of ")
                    .append(sv)
                    .append(" is vulnerable.")
                    .append("\n\n");
            desc.append("Vulnerability Details:").append("\n");
            desc.append("  ")
                    .append(nz(v.getTitle(), nz(v.getCveId(), "Vulnerability")))
                    .append("\n");
            if (!cve.isBlank()) {
                desc.append("  CVE ID: ").append(cve).append("\n");
            }
            desc.append("  Severity: ").append(severity);
            if (v.getCvssScore() > 0) {
                desc.append(" (CVSS: ").append(String.format("%.1f", v.getCvssScore())).append(")");
            }
            desc.append("\n");

            String vulnDesc = nz(v.getShortDescription(), nz(v.getDescription(), ""));
            if (!vulnDesc.isBlank()) {
                desc.append("  Description: ").append(vulnDesc).append("\n");
            }
        } else if (list.size() > 1) {
            // Multiple vulnerabilities - Nessus style list
            title = "Multiple vulnerabilities in " + software + " version " + version;

            desc.append("The detected version of ")
                    .append(sv)
                    .append(" has multiple known vulnerabilities.")
                    .append("\n\n");
            desc.append("List of Vulnerabilities:").append("\n");
            desc.append(SEPARATOR_LINE).append("\n");

            int count = 0;
            for (VulnerabilityInfo v : list) {
                count++;
                String cve = nz(v.getCveId(), "");
                String severity = getSeverityLabel(v);
                String vulnTitle = nz(v.getTitle(), "Vulnerability");

                desc.append("\n").append(count).append(". ");
                if (!cve.isBlank()) {
                    desc.append(cve).append(" - ");
                }
                desc.append(vulnTitle).append("\n");

                desc.append("   Severity: ").append(severity);
                if (v.getCvssScore() > 0) {
                    desc.append(" (CVSS: ")
                            .append(String.format("%.1f", v.getCvssScore()))
                            .append(")");
                }
                desc.append("\n");

                String vulnDesc = nz(v.getShortDescription(), nz(v.getDescription(), ""));
                if (!vulnDesc.isBlank()) {
                    // Truncate long descriptions
                    String shortDesc =
                            vulnDesc.length() > MAX_DESCRIPTION_LENGTH ? 
                            vulnDesc.substring(0, MAX_DESCRIPTION_LENGTH) + "..." : vulnDesc;
                    desc.append("   ").append(shortDesc).append("\n");
                }
            }
        } else {
            title = "Software Version Detected: " + sv;
            desc.append("Detected software: ").append(sv).append("\n");
            desc.append("No known vulnerabilities found in the vulnerability database.");
        }

        LinkedHashSet<String> refs = new LinkedHashSet<>();
        for (VulnerabilityInfo v : list) {
            String link = nz(v.getLink(), "");
            if (!link.isBlank()) refs.add(link);
            if (v.getReferences() != null)
                for (String r : v.getReferences()) if (r != null && !r.isBlank()) refs.add(r);
        }

        LinkedHashSet<String> tags = new LinkedHashSet<>();
        tags.add("vulnerability");
        for (VulnerabilityInfo v : list) {
            if (!isBlank(v.getFamily())) tags.add(v.getFamily().toLowerCase(Locale.ROOT));
            if (!isBlank(v.getRecordType())) tags.add(v.getRecordType().toLowerCase(Locale.ROOT));
            String c = nz(v.getCveId(), "");
            if (!c.isBlank()) tags.add(c);
        }
        if (!isBlank(software)) tags.add(software.toLowerCase(Locale.ROOT));
        if (!isBlank(version)) tags.add(version.toLowerCase(Locale.ROOT));

        String solution =
                "Upgrade " + sv + " to the latest version to address these vulnerabilities.";
        return new Report(
                title,
                desc.toString().trim(),
                solution,
                String.join("\n", refs),
                String.join(", ", tags));
    }

    private static String getSeverityLabel(VulnerabilityInfo v) {
        // Use API-provided severity directly, fallback to CVSS only if severity not available
        String apiSeverity = v.getSeverity();
        if (apiSeverity != null && !apiSeverity.isBlank()) {
            return apiSeverity.toUpperCase(Locale.ROOT);
        }
        // Fallback: derive from CVSS score only when API doesn't provide severity
        double cvssScore = v.getCvssScore();
        if (cvssScore >= 9.0) return "CRITICAL";
        if (cvssScore >= 7.0) return "HIGH";
        if (cvssScore >= 4.0) return "MEDIUM";
        if (cvssScore > 0.0) return "LOW";
        return "UNKNOWN";
    }

    private static String keyFor(VulnerabilityInfo v) {
        String cve = nz(v.getCveId(), "").trim().toUpperCase(Locale.ROOT);
        if (!cve.isBlank()) return "CVE:" + cve;
        String t = nz(v.getTitle(), "").replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
        if (!t.isBlank()) return "T:" + t;
        String d =
                nz(v.getShortDescription(), nz(v.getDescription(), ""))
                        .replaceAll("\\s+", " ")
                        .trim()
                        .toLowerCase(Locale.ROOT);
        return "D:" + d;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String nz(String s, String def) {
        return isBlank(s) ? def : s;
    }

    public static final class Report {
        public final String title, description, solution, references, tags;

        public Report(
                String title, String description, String solution, String references, String tags) {
            this.title = title;
            this.description = description;
            this.solution = solution;
            this.references = references;
            this.tags = tags;
        }
    }
}
