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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VersionUtil {

    private static final Pattern VERSION_PATTERN =
            Pattern.compile("^(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?(?:\\.(\\d+))?.*$");

    public static int[] parseVersion(String version) {
        if (version == null || version.isBlank()) return new int[0];
        Matcher m = VERSION_PATTERN.matcher(version);
        if (!m.matches()) return new int[0];

        int[] parts = new int[4];
        parts[0] = m.group(1) != null ? Integer.parseInt(m.group(1)) : 0;
        parts[1] = m.group(2) != null ? Integer.parseInt(m.group(2)) : 0;
        parts[2] = m.group(3) != null ? Integer.parseInt(m.group(3)) : 0;
        parts[3] = m.group(4) != null ? Integer.parseInt(m.group(4)) : 0;
        return parts;
    }

    public static int compareVersions(String v1, String v2) {
        int[] parts1 = parseVersion(v1);
        int[] parts2 = parseVersion(v2);

        for (int i = 0; i < 4; i++) {
            int cmp = Integer.compare(parts1[i], parts2[i]);
            if (cmp != 0) return cmp;
        }
        return 0;
    }

    public static boolean isVersionInRange(
            String version,
            String start,
            String end,
            boolean startInclusive,
            boolean endInclusive) {
        if (version == null || version.isBlank()) return false;

        int cmpStart = -1;
        int cmpEnd = 1;

        if (start != null && !start.isBlank() && !start.equals("*")) {
            cmpStart = compareVersions(version, start);
        }
        if (end != null && !end.isBlank() && !end.equals("*")) {
            cmpEnd = compareVersions(version, end);
        }

        boolean afterStart = startInclusive ? cmpStart >= 0 : cmpStart > 0;
        boolean beforeEnd = endInclusive ? cmpEnd <= 0 : cmpEnd < 0;

        return afterStart && beforeEnd;
    }

    public static String extractVersionFromCpe(String cpe) {
        if (cpe == null || !cpe.startsWith("cpe:2.3:")) return null;
        String[] parts = cpe.split(":");
        if (parts.length < 6) return null;
        String version = parts[5];
        return "*".equals(version) || version.isBlank() ? null : version;
    }

    public static boolean isVersionAffected(String detectedVersion, String cpeMatchCriteria) {
        if (detectedVersion == null || detectedVersion.isBlank()) return true;
        if (cpeMatchCriteria == null || cpeMatchCriteria.isBlank()) return true;

        // CPE match criteria format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        // or with ranges using * or other wildcards
        String[] parts = cpeMatchCriteria.split(":");
        if (parts.length < 6) return true;

        String version = parts[5];

        // If version is * or empty, it applies to all versions
        if ("*".equals(version) || version.isBlank()) return true;

        // If exact version match
        if (!version.contains("*") && !version.contains("?")) {
            return compareVersions(detectedVersion, version) == 0;
        }

        // Handle wildcards - treat * as wildcard for version parts
        int[] detected = parseVersion(detectedVersion);
        int[] cpeVer = parseVersion(version);

        // Check each part, treating * as wildcard
        for (int i = 0; i < Math.min(detected.length, cpeVer.length); i++) {
            // If CPE version part is not zero (indicating a wildcard in our parsed version)
            if (cpeVer[i] != 0) {
                // Compare actual version parts
                if (detected[i] != cpeVer[i]) {
                    return false;
                }
            }
            // If cpeVer[i] is 0, it means there was a wildcard or missing part, so it matches any value
        }

        // Handle case where CPE version has more specific parts than detected version
        for (int i = detected.length; i < cpeVer.length; i++) {
            if (cpeVer[i] != 0) {
                // CPE has more specific parts that detected version doesn't have
                return false;
            }
        }

        return true;
    }
}
