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
package org.zaproxy.addon.softwareversionreporter.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class EnrichmentResult {
    private String software;
    private String version;
    private String source;
    private String cpe;
    private List<VulnerabilityInfo> vulnerabilities = new ArrayList<>();

    public EnrichmentResult() {}

    public EnrichmentResult(String software, String version) {
        this.software = software;
        this.version = version;
    }

    public String getSoftware() {
        return software;
    }

    public void setSoftware(String software) {
        this.software = software;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getCpe() {
        return cpe;
    }

    public void setCpe(String cpe) {
        this.cpe = cpe;
    }

    public List<VulnerabilityInfo> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<VulnerabilityInfo> vulnerabilities) {
        this.vulnerabilities = vulnerabilities != null ? vulnerabilities : new ArrayList<>();
    }

    public boolean hasVulnerabilities() {
        return vulnerabilities != null && !vulnerabilities.isEmpty();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EnrichmentResult)) return false;
        EnrichmentResult that = (EnrichmentResult) o;
        return Objects.equals(software, that.software)
                && Objects.equals(version, that.version)
                && Objects.equals(source, that.source)
                && Objects.equals(cpe, that.cpe)
                && Objects.equals(vulnerabilities, that.vulnerabilities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(software, version, source, cpe, vulnerabilities);
    }

    @Override
    public String toString() {
        return "EnrichmentResult{software='"
                + software
                + "', version='"
                + version
                + "', source='"
                + source
                + "', cpe='"
                + cpe
                + "', vulnerabilities="
                + (vulnerabilities != null ? vulnerabilities.size() : 0)
                + "}";
    }

    public static class VulnerabilityInfo {
        private String cveId;
        private String title;
        private String shortDescription;
        private String description;
        private String link;
        private double cvssScore;
        private String severity;
        // Newly added for tagging
        private String family;
        private String recordType;
        private List<String> references = new ArrayList<>();

        public String getCveId() {
            return cveId;
        }

        public void setCveId(String cveId) {
            this.cveId = cveId;
        }

        public String getTitle() {
            return title;
        }

        public void setTitle(String title) {
            this.title = title;
        }

        public String getShortDescription() {
            return shortDescription;
        }

        public void setShortDescription(String shortDescription) {
            this.shortDescription = shortDescription;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getLink() {
            return link;
        }

        public void setLink(String link) {
            this.link = link;
        }

        public double getCvssScore() {
            return cvssScore;
        }

        public void setCvssScore(double cvssScore) {
            this.cvssScore = cvssScore;
        }

        public String getSeverity() {
            return severity;
        }

        public void setSeverity(String severity) {
            this.severity = severity;
        }

        public String getFamily() {
            return family;
        }

        public void setFamily(String family) {
            this.family = family;
        }

        public String getRecordType() {
            return recordType;
        }

        public void setRecordType(String recordType) {
            this.recordType = recordType;
        }

        public List<String> getReferences() {
            return references;
        }

        public void setReferences(List<String> references) {
            this.references = references != null ? references : new ArrayList<>();
        }

        @Override
        public String toString() {
            return "VulnerabilityInfo{cveId='"
                    + cveId
                    + "', title='"
                    + title
                    + "', cvssScore="
                    + cvssScore
                    + ", severity='"
                    + severity
                    + "', family='"
                    + family
                    + "', recordType='"
                    + recordType
                    + "'}";
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof VulnerabilityInfo)) return false;
            VulnerabilityInfo that = (VulnerabilityInfo) o;
            return Double.compare(that.cvssScore, cvssScore) == 0
                    && Objects.equals(cveId, that.cveId)
                    && Objects.equals(title, that.title)
                    && Objects.equals(shortDescription, that.shortDescription)
                    && Objects.equals(description, that.description)
                    && Objects.equals(link, that.link)
                    && Objects.equals(severity, that.severity)
                    && Objects.equals(family, that.family)
                    && Objects.equals(recordType, that.recordType)
                    && Objects.equals(references, that.references);
        }

        @Override
        public int hashCode() {
            return Objects.hash(
                    cveId,
                    title,
                    shortDescription,
                    description,
                    link,
                    cvssScore,
                    severity,
                    family,
                    recordType,
                    references);
        }
    }
}
