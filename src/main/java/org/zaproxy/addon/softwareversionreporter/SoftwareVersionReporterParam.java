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

import org.apache.commons.configuration.Configuration;

public class SoftwareVersionReporterParam {
    private static final String ENRICHMENT_ENABLED_KEY =
            "softwareversionreporter.enrichment.enabled";
    private static final String API_PROVIDER_KEY = "softwareversionreporter.enrichment.provider";
    private static final String NVD_API_KEY = "softwareversionreporter.nvd.apikey";
    private static final String VULNERS_API_KEY = "softwareversionreporter.vulners.apikey";
    private static final String VULDB_API_KEY = "softwareversionreporter.vuldb.apikey";
    private static final String ENRICH_ON_NO_VERSION_KEY =
            "softwareversionreporter.enrichment.whenNoVersion";

    private boolean enrichmentEnabled = true;
    private String apiProvider = "nvd";
    private String nvdApiKey = "";
    private String vulnersApiKey = "";
    private String vuldbApiKey = "";
    private boolean enrichWhenNoVersion = false;

    public void parse(Configuration conf) {
        if (conf == null) return;
        enrichmentEnabled = conf.getBoolean(ENRICHMENT_ENABLED_KEY, enrichmentEnabled);
        apiProvider = conf.getString(API_PROVIDER_KEY, apiProvider);
        nvdApiKey = conf.getString(NVD_API_KEY, nvdApiKey);
        vulnersApiKey = conf.getString(VULNERS_API_KEY, vulnersApiKey);
        vuldbApiKey = conf.getString(VULDB_API_KEY, vuldbApiKey);
        enrichWhenNoVersion = conf.getBoolean(ENRICH_ON_NO_VERSION_KEY, enrichWhenNoVersion);
    }

    public void save(Configuration conf) {
        if (conf == null) return;
        conf.setProperty(ENRICHMENT_ENABLED_KEY, enrichmentEnabled);
        conf.setProperty(API_PROVIDER_KEY, apiProvider);
        conf.setProperty(NVD_API_KEY, nvdApiKey);
        conf.setProperty(VULNERS_API_KEY, vulnersApiKey);
        conf.setProperty(VULDB_API_KEY, vuldbApiKey);
        conf.setProperty(ENRICH_ON_NO_VERSION_KEY, enrichWhenNoVersion);
    }

    public boolean isEnrichmentEnabled() {
        return enrichmentEnabled;
    }

    public void setEnrichmentEnabled(boolean enabled) {
        this.enrichmentEnabled = enabled;
    }

    public String getApiProvider() {
        return apiProvider;
    }

    public void setApiProvider(String provider) {
        this.apiProvider = provider;
    }

    public String getNvdApiKey() {
        return nvdApiKey;
    }

    public void setNvdApiKey(String key) {
        this.nvdApiKey = key;
    }

    public String getVulnersApiKey() {
        return vulnersApiKey;
    }

    public void setVulnersApiKey(String key) {
        this.vulnersApiKey = key;
    }

    public String getVuldbApiKey() {
        return vuldbApiKey;
    }

    public void setVuldbApiKey(String key) {
        this.vuldbApiKey = key;
    }

    public boolean isEnrichWhenNoVersion() {
        return enrichWhenNoVersion;
    }

    public void setEnrichWhenNoVersion(boolean v) {
        this.enrichWhenNoVersion = v;
    }
}
