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

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.softwareversionreporter.DetectionRuleLoader.DetectionRule;
import org.zaproxy.addon.softwareversionreporter.ui.SoftwareVersionReporterOptionsPanel;

public class ExtensionSoftwareVersionReporter extends ExtensionAdaptor {
    private static final Logger LOGGER =
            LogManager.getLogger(ExtensionSoftwareVersionReporter.class);
    private static ExtensionSoftwareVersionReporter instance;

    private SoftwareVersionReporterParam param;
    private VulnerabilityEnrichmentService enrichmentService;
    private List<DetectionRule> detectionRules;

    public ExtensionSoftwareVersionReporter() {
        super("ExtensionSoftwareVersionReporter");
        instance = this;
    }

    public static ExtensionSoftwareVersionReporter getInstance() {
        return instance;
    }

    @Override
    public void init() {
        super.init();
        // Only instantiate objects — do NOT access getModel() here
        param = new SoftwareVersionReporterParam();
        detectionRules = new DetectionRuleLoader().getRules();
        LOGGER.info("SVR init: detection rules loaded={}", detectionRules.size());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // Parse config now that model is available
        if (getModel() != null && getModel().getOptionsParam() != null) {
            param.parse(getModel().getOptionsParam().getConfig());
            enrichmentService = new VulnerabilityEnrichmentService(param);
            LOGGER.info("SVR enrichment service initialized");
        } else {
            LOGGER.warn("SVR model/options not available during hook");
        }

        if (getView() != null) {
            extensionHook
                    .getHookView()
                    .addOptionPanel(new SoftwareVersionReporterOptionsPanel(getParam()));
        }
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("softwareversionreporter.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("softwareversionreporter.desc");
    }

    public SoftwareVersionReporterParam getParam() {
        return param;
    }

    public VulnerabilityEnrichmentService getEnrichmentService() {
        return enrichmentService;
    }

    public List<DetectionRule> getDetectionRules() {
        return detectionRules;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
    }
}
