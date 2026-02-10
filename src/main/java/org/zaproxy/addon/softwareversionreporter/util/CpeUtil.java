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

public class CpeUtil {
    public static String build(String vendor, String product, String version) {
        String v = escapeCpe(norm(vendor));
        String p = escapeCpe(norm(product));
        String ver = (version == null || version.isBlank()) ? "*" : escapeCpe(version);
        return "cpe:2.3:a:" + v + ":" + p + ":" + ver + "::*:*:*:*:*:*";
    }

    public static String buildProductOnly(String vendor, String product) {
        String v = escapeCpe(norm(vendor));
        String p = escapeCpe(norm(product));
        return "cpe:2.3:a:" + v + ":" + p + ":*:*:*:*:*:*:*:*";
    }

    public static Parts parse(String cpe) {
        if (cpe == null || !cpe.startsWith("cpe:2.3:")) return new Parts(null, null, null);
        String[] s = cpe.split(":");
        if (s.length >= 6) return new Parts(s[3], s[4], s[5]);
        return new Parts(null, null, null);
    }

    private static String norm(String s) {
        return (s == null || s.isBlank())
                ? "*"
                : s.toLowerCase().replaceAll("[\\s_]+", "_").replaceAll("[^a-z0-9_\\-\\.]", "_");
    }

    private static String escapeCpe(String s) {
        if (s == null || s.isBlank()) return "*";
        // CPE 2.3 escaping: ! " # $ % & ' ( ) * + , - . / : ; < = > @ [ \ ] ^ ` { | } ~
        // These characters must be escaped with backslash
        return s.replace("\\", "\\\\")
                .replace("!", "\\!")
                .replace("\"", "\\\"")
                .replace("#", "\\#")
                .replace("$", "\\$")
                .replace("%", "\\%")
                .replace("&", "\\&")
                .replace("'", "\\'")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replace("*", "\\*")
                .replace("+", "\\+")
                .replace(",", "\\,")
                .replace("-", "\\-")
                .replace(".", "\\.")
                .replace("/", "\\/")
                .replace(":", "\\:")
                .replace(";", "\\;")
                .replace("<", "\\<")
                .replace("=", "\\=")
                .replace(">", "\\>")
                .replace("@", "\\@")
                .replace("[", "\\[")
                .replace("]", "\\]")
                .replace("^", "\\^")
                .replace("`", "\\`")
                .replace("{", "\\{")
                .replace("|", "\\|")
                .replace("}", "\\}")
                .replace("~", "\\~");
    }

    public static final class Parts {
        public final String vendor, product, version;

        public Parts(String vendor, String product, String version) {
            this.vendor = vendor;
            this.product = product;
            this.version = version;
        }
    }
}
