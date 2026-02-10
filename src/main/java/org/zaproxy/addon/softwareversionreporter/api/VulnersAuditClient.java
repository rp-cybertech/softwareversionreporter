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
import java.util.ArrayList;
import java.util.List;
import org.zaproxy.addon.softwareversionreporter.VulnerabilityMappers;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult.VulnerabilityInfo;

public class VulnersAuditClient {
    private static final ObjectMapper M = new ObjectMapper();

    public EnrichmentResult audit(String software, String version, String json) throws Exception {
        EnrichmentResult er = new EnrichmentResult(software, version);
        er.setSource("Vulners");
        JsonNode root = M.readTree(json);

        List<VulnerabilityInfo> out = new ArrayList<>();
        JsonNode items = root.path("data").path("search");
        if (items.isArray()) {
            for (JsonNode it : items) {
                JsonNode src = it.has("_source") ? it.path("_source") : it;
                VulnerabilityInfo vi = VulnerabilityMappers.mapVulnersItem(src);
                if (vi != null) out.add(vi);
            }
        }
        er.setVulnerabilities(out);
        return er;
    }
}
