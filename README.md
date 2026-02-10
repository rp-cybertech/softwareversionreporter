# Software Version Reporter - OWASP ZAP Add-on

A powerful OWASP ZAP extension that automatically detects software versions in HTTP responses and enriches findings with comprehensive vulnerability intelligence from multiple sources.

## 🚀 Key Features

- **🔍 Passive Scanning** - Automatically detects software versions from HTTP headers and response bodies
- **🛡️ Multi-Source Enrichment** - Integrate vulnerability data from NVD, Vulners, and VulDB APIs
- **⚙️ Easy Configuration** - Simple API key management through ZAP's intuitive Options panel
- **📝 Detailed Reporting** - Generate comprehensive vulnerability alerts with CVE references and severity ratings
- **📊 Smart Severity** - Informational alerts for version detection, risk-based alerts for known vulnerabilities

## 🔧 System Requirements

- **OWASP ZAP**: 2.15.0 or higher
- **Java**: 11+ (compatible with ZAP requirements)
- **Memory**: Minimum 2GB RAM recommended
- **Network**: Internet access for vulnerability API queries

## 📦 Installation

### Option 1: From Source (Recommended for Development)

1. **Clone the repository** into ZAP's addOns folder:
   ```bash
   git clone https://github.com/raghu844/softwareversionreporter.git zap-extensions/addOns/softwareversionreporter
   ```

2. **Build and deploy** the add-on:
   ```bash
   ./gradlew :addOns:softwareversionreporter:clean :addOns:softwareversionreporter:build
   ./gradlew :addOns:softwareversionreporter:copyZapAddOn --into=$HOME/.ZAP/plugin/
   ```

3. **Restart ZAP** to load the extension

### Option 2: Pre-built Package

1. **Download** the latest add-on package: `softwareversionreporter-alpha-1.zap`

2. **Copy** the `.zap` file into your ZAP plugin directory:
   - **Linux/Mac**: `~/.ZAP/plugin/`
   - **Windows**: `C:\Users\<YourUsername>\.ZAP\plugin\`

3. **Restart ZAP** to automatically load the extension

## 🔌 API Configuration

### Supported Vulnerability Databases

| Provider | API Endpoint | Rate Limits | Authentication |
|----------|--------------|-------------|----------------|
| **NVD** | https://services.nvd.nist.gov/rest/json/cves/2.0 | 5 req/sec (no key), 50 req/sec (with key) | Optional API Key |
| **Vulners** | https://vulners.com/api/v3/ | 5 req/sec | Optional API Key |
| **VulDB** | https://vuldb.com/?api | 4 req/sec | Optional API Key |

### Setup

1. **Open OWASP ZAP**
2. **Navigate** to **Options → Software Version Reporter**
3. **Enter** your API keys for desired providers:
   - **NVD**: [Request API Key](https://nvd.nist.gov/developers/request-an-api-key)
   - **Vulners**: [Get API Key](https://vulners.com)
   - **VulDB**: [Get API Key](https://vuldb.com)
4. **Click** **Save** to persist settings

## 🎯 Usage

1. **Perform web scans** as usual in ZAP
2. The extension **passively detects** software versions from HTTP responses
3. **Detected versions** appear as alerts in the **Alerts** tab:
   - **Informational** (blue): Version detected, no known vulnerabilities
   - **Low/Medium/High** (colored): Version detected with known vulnerabilities

## 🔧 Troubleshooting

### Common Issues

**API Key Problems**
- Verify API keys are correctly entered in ZAP Options
- Check for leading/trailing spaces in API keys
- Test API endpoints manually for connectivity

**Missing Detections**
- Ensure passive scanning is enabled in ZAP
- Verify response content contains version information

**Performance Issues**
- Disable unused API providers for faster scanning
- Consider API rate limits during large scans
- Monitor ZAP logs for API error messages

### Debug Logging

Enable debug logging in ZAP:
```
org.zaproxy.addon.softwareversionreporter=DEBUG
```

## 🔒 Security Considerations

- **API keys** are stored in ZAP's secure configuration
- **Never commit** API keys to version control
- Only **HTTP responses** are analyzed (no request payloads)
- **Rate limiting** is built-in to prevent API abuse

## 🤝 Contributing

We welcome contributions!

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'Add amazing feature'`
4. **Push** to your branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

## 📞 Support

- **GitHub**: [raghu844](https://github.com/raghu844)
- **LinkedIn**: [Raghavendra Patil](https://www.linkedin.com/in/raghavendra-patil-8a0330197)
- **Issues**: [GitHub Issues](https://github.com/raghu844/softwareversionreporter/issues)

## 📄 License

This project is licensed under the Apache License 2.0.

## 🙏 Acknowledgments

- **OWASP ZAP Team** - For the amazing security testing platform
- **NVD, Vulners, VulDB** - For providing vulnerability intelligence APIs

---

**⭐ Star this repository if you find it useful!**
