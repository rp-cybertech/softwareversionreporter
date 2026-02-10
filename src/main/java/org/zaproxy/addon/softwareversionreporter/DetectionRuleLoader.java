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

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DetectionRuleLoader {
    private static final Logger LOGGER = LogManager.getLogger(DetectionRuleLoader.class);
    private static final String RULES_FILE =
            "/org/zaproxy/addon/softwareversionreporter/detection-rules.tsv";
    private List<DetectionRule> rules;

    public DetectionRuleLoader() {
        this.rules = loadRules();
    }

    public List<DetectionRule> getRules() {
        return rules;
    }

    private List<DetectionRule> loadRules() {
        List<DetectionRule> list = new ArrayList<>();
        InputStream is = null;
        BufferedReader br = null;
        try {
            is = getClass().getResourceAsStream(RULES_FILE);
            if (is == null) {
                LOGGER.error("Detection rules file not found: {}", RULES_FILE);
                return Collections.unmodifiableList(list);
            }
            br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            String line;
            boolean firstLine = true;
            while ((line = br.readLine()) != null) {
                if (firstLine) {
                    firstLine = false;
                    continue;
                }
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\t");
                if (parts.length >= 5) {
                    list.add(
                            new DetectionRule(
                                    parts[2], // software
                                    parts[1], // type
                                    parts[0], // pattern
                                    parts.length > 4 ? parts[4] : "", // vendor
                                    parts.length > 5 ? parts[5] : "" // product
                                    ));
                }
            }
            LOGGER.info("Loaded {} detection rules", list.size());
        } catch (java.io.IOException ioEx) {
            LOGGER.error("IO error loading detection rules file: {}", RULES_FILE, ioEx);
        } catch (SecurityException secEx) {
            LOGGER.error("Security error accessing detection rules file: {}", RULES_FILE, secEx);
        } catch (Exception e) {
            LOGGER.error("Unexpected error loading detection rules", e);
        } finally {
            // Close resources in reverse order of creation
            if (br != null) {
                try {
                    br.close();
                } catch (Exception e) {
                    LOGGER.warn("Error closing BufferedReader", e);
                }
            }
            if (is != null) {
                try {
                    is.close();
                } catch (Exception e) {
                    LOGGER.warn("Error closing InputStream", e);
                }
            }
        }
        return Collections.unmodifiableList(list);
    }

    public static class DetectionRule {
        private final String software, type, pattern, cpeVendor, cpeProduct;

        public DetectionRule(
                String software, String type, String pattern, String cpeVendor, String cpeProduct) {
            this.software = software;
            this.type = type;
            this.pattern = pattern;
            this.cpeVendor = cpeVendor;
            this.cpeProduct = cpeProduct;
        }

        public String getSoftware() {
            return software;
        }

        public String getType() {
            return type;
        }

        public String getPattern() {
            return pattern;
        }

        public String getCpeVendor() {
            return cpeVendor;
        }

        public String getCpeProduct() {
            return cpeProduct;
        }
    }
}
