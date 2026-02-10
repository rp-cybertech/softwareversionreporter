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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.softwareversionreporter.VulnerabilityEnrichmentService;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

public class ProviderHealthCheck {
    private static final Logger LOGGER = LogManager.getLogger(ProviderHealthCheck.class);

    public static void run(VulnerabilityEnrichmentService svc) {
        try {
            EnrichmentResult v = svc.query("nginx", "1.21.6", "nginx", "nginx");
            LOGGER.info(
                    "SVR health Vulners items={}", 
                    v != null && v.getVulnerabilities() != null ? v.getVulnerabilities().size() : 0);
            EnrichmentResult n = svc.query("php", "5.6.0", "php", "php");
            LOGGER.info("SVR health NVD items={}", 
                    n != null && n.getVulnerabilities() != null ? n.getVulnerabilities().size() : 0);
        } catch (Exception e) {
            LOGGER.warn("SVR health error", e);
        }
    }
}
