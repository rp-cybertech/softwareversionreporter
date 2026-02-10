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
package org.zaproxy.addon.softwareversionreporter.ui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.softwareversionreporter.SoftwareVersionReporterParam;

public class SoftwareVersionReporterOptionsPanel extends AbstractParamPanel {
    private static final long serialVersionUID = 1L;

    private transient SoftwareVersionReporterParam param;

    private JCheckBox enrichmentEnabled;
    private JCheckBox enrichWhenNoVersion;
    private JComboBox<String> provider;
    private JTextField nvdApiKey;
    private JTextField vulnersApiKey;
    private JTextField vuldbApiKey;

    public SoftwareVersionReporterOptionsPanel(SoftwareVersionReporterParam param) {
        this.param = param;
        setName(Constant.messages.getString("softwareversionreporter.name"));
        setLayout(new GridBagLayout());
        buildUI();
        initFromParam(param);
    }

    private void buildUI() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(
                BorderFactory.createTitledBorder(
                        Constant.messages.getString("softwareversionreporter.desc")));

        int y = 0;

        enrichmentEnabled = new JCheckBox("Enable vulnerability enrichment");
        gbc.gridx = 0;
        gbc.gridy = y++;
        gbc.gridwidth = 2;
        panel.add(enrichmentEnabled, gbc);

        enrichWhenNoVersion = new JCheckBox("Enrich even when version is missing");
        gbc.gridx = 0;
        gbc.gridy = y++;
        gbc.gridwidth = 2;
        panel.add(enrichWhenNoVersion, gbc);

        gbc.gridwidth = 1;
        panel.add(new JLabel("Provider"), grid(0, y));
        provider = new JComboBox<>(new String[] {"nvd", "vulners", "vuldb"});
        panel.add(provider, grid(1, y++));

        panel.add(new JLabel("NVD API Key"), grid(0, y));
        nvdApiKey = new JTextField();
        panel.add(nvdApiKey, grid(1, y++));

        panel.add(new JLabel("Vulners API Key"), grid(0, y));
        vulnersApiKey = new JTextField();
        panel.add(vulnersApiKey, grid(1, y++));

        panel.add(new JLabel("VulDB API Key"), grid(0, y));
        vuldbApiKey = new JTextField();
        panel.add(vuldbApiKey, grid(1, y++));

        GridBagConstraints pg = new GridBagConstraints();
        pg.gridx = 0;
        pg.gridy = 0;
        pg.weightx = 1.0;
        pg.weighty = 1.0;
        pg.fill = GridBagConstraints.BOTH;
        add(panel, pg);
    }

    private GridBagConstraints grid(int x, int y) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = x;
        gbc.gridy = y;
        gbc.insets = new Insets(2, 2, 2, 2);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = (x == 1) ? 1.0 : 0.0;
        return gbc;
    }

    private void initFromParam(SoftwareVersionReporterParam p) {
        if (p == null) return;
        enrichmentEnabled.setSelected(p.isEnrichmentEnabled());
        enrichWhenNoVersion.setSelected(p.isEnrichWhenNoVersion());
        String apiProvider = p.getApiProvider() != null ? p.getApiProvider() : "nvd";
        provider.setSelectedItem(apiProvider);
        nvdApiKey.setText(p.getNvdApiKey() != null ? p.getNvdApiKey() : "");
        vulnersApiKey.setText(p.getVulnersApiKey() != null ? p.getVulnersApiKey() : "");
        vuldbApiKey.setText(p.getVuldbApiKey() != null ? p.getVuldbApiKey() : "");
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam opts = (OptionsParam) obj;
        if (this.param == null) {
            this.param = new SoftwareVersionReporterParam();
        }
        this.param.parse(opts.getConfig());
        initFromParam(this.param);
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam opts = (OptionsParam) obj;
        if (this.param == null) this.param = new SoftwareVersionReporterParam();
        this.param.setEnrichmentEnabled(enrichmentEnabled.isSelected());
        this.param.setEnrichWhenNoVersion(enrichWhenNoVersion.isSelected());
        Object sel = provider.getSelectedItem();
        this.param.setApiProvider(sel != null ? sel.toString() : "nvd");
        this.param.setNvdApiKey(nonNull(nvdApiKey.getText()));
        this.param.setVulnersApiKey(nonNull(vulnersApiKey.getText()));
        this.param.setVuldbApiKey(nonNull(vuldbApiKey.getText()));
        this.param.save(opts.getConfig());
    }

    @Override
    public String getHelpIndex() {
        return null;
    }

    private static String nonNull(String s) {
        return s != null ? s.trim() : "";
    }
}
