# 🛡️ Phishing Detector Browser Extension

A professional-grade browser extension that provides **real-time phishing and scam detection** using advanced multi-layered analysis.

## ✨ Features

### 🔍 Multi-Layered Detection
- **Advanced URL Analysis**: Detects suspicious domains, typosquatting with keyboard proximity attacks (rn→m), character substitutions (0→o, 1→l), homograph attacks, and malicious TLDs
- **Content Scanning**: Identifies urgency tactics, misleading links, hidden iframes, and obfuscated scripts
- **Intelligent Form Analysis**: Monitors credential harvesting with smart detection that reduces false positives on legitimate HTTPS sites
- **Behavioral Analysis**: Catches auto-submit forms, popup spam, and clipboard manipulation

### ⚡ Real-Time Protection
- **Live Monitoring**: Uses debounced MutationObserver for efficient dynamic page change detection
- **Anti-Bypass Protection**: Warning overlays use Shadow DOM to prevent tampering by malicious pages
- **Instant Warnings**: Full-page overlays for high-risk sites with detailed threat information and security tips
- **Risk Scoring**: 0-100 risk assessment with 5 threat levels (Safe, Low, Medium, High, Critical)
- **Smart Form Protection**: Alerts before submitting credentials to suspicious sites

### 🎨 Modern Interface
- **Visual Risk Indicator**: Color-coded badge shows threat level at a glance
- **Enhanced Popup**: Risk scores, categorized threats (URL, Form, Content, Behavior), and protection statistics
- **Animated Warnings**: Professional overlays with priority indicators and educational security tips
- **Statistics Tracking**: Monitor sites checked and threats blocked
- **Session Memory**: Dismissed warnings are remembered to avoid repeated interruptions

## 🚀 Installation

### Chrome / Edge / Brave
1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top-right)
4. Click "Load unpacked"
5. Select the extension folder
6. The Phishing Detector icon will appear in your toolbar!

### Firefox
1. Download or clone this repository
2. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on"
4. Select the `manifest.json` file from the extension folder
5. The extension is now active!

## 🔒 How It Works

### Detection Engine
The extension uses a sophisticated **multi-layered analysis system**:

1. **URL Analysis** (40 points max)
   - Checks for non-HTTPS on sensitive pages
   - Detects suspicious TLDs (.tk, .ml, .xyz, etc.)
   - Identifies IP addresses instead of domain names
   - Catches homograph attacks (lookalike characters)
   - **NEW**: Advanced typosquatting with keyboard proximity detection (e.g., 'arnaz0n.com')
   - **NEW**: Character substitution detection (0→o, 1→l, @→a)
   - **NEW**: Doubled character detection (gooogle.com)

2. **Content Analysis** (30 points max)
   - Scans for urgency language ("act now", "limited time")
   - Detects misleading links
   - Finds hidden iframes
   - Identifies obfuscated JavaScript

3. **Form Analysis** (35 points max)
   - Monitors password fields on non-HTTPS pages
   - Detects forms submitting to external domains
   - Flags credit card and SSN requests
   - **NEW**: Smart scoring - reduced penalties for legitimate HTTPS login forms on known domains

4. **Behavioral Analysis** (20 points max)
   - Catches auto-submit forms
   - Detects popup spam
   - Identifies clipboard manipulation

### Risk Levels
- **Safe** (0-19): No significant threats detected
- **Low** (20-39): Minor concerns, proceed with caution
- **Medium** (40-59): Multiple suspicious indicators
- **High** (60-79): Strong phishing indicators
- **Critical** (80-100): Extremely dangerous, leave immediately

## 📊 What Gets Detected

### ✅ Phishing Attempts
- Fake login pages for banks, social media, email
- Typosquatted domains (e.g., paypa1.com instead of paypal.com)
- Homograph attacks using lookalike characters
- Credential harvesting forms

### ✅ Scam Indicators
- Urgency tactics ("act now or lose access")
- Prize/lottery scams
- Fake security alerts
- Suspicious payment requests

### ✅ Technical Threats
- Forms on non-HTTPS pages requesting passwords
- Hidden iframes for tracking
- Obfuscated malicious scripts
- External form submissions

## 🎯 Usage

### Automatic Protection
Simply browse the web normally. The extension works automatically:
- ✅ Green badge = Site is safe
- 🔵 Blue badge = Low risk
- 🟡 Yellow badge = Medium risk
- 🟠 Orange badge = High risk
- 🔴 Red badge = Critical threat

### Viewing Details
Click the extension icon to see:
- Current site's risk score
- Specific threats detected
- Total sites checked
- Threats blocked

### Warning Overlays
When visiting dangerous sites, you'll see a full-page warning with:
- Risk level and score
- List of detected threats
- Options to go back or proceed (at your own risk)

## 🔐 Privacy

This extension:
- ✅ **Does NOT collect or transmit any data**
- ✅ **All analysis happens locally in your browser**
- ✅ **No external servers or APIs used**
- ✅ **No tracking or analytics**
- ✅ **Open source - review the code yourself**

## 🛠️ Technical Details

**Built with:**
- Manifest V3 (latest Chrome extension standard)
- Vanilla JavaScript (no dependencies)
- Modern CSS with animations
- Real-time DOM monitoring (MutationObserver)

**Compatible with:**
- Google Chrome (v88+)
- Microsoft Edge (v88+)
- Brave Browser
- Mozilla Firefox (v109+)

## ⚠️ Limitations

- Detection is based on patterns and heuristics, not perfect
- May show false positives on legitimate sites with unusual patterns (we've minimized these with smart scoring)
- Cannot detect all sophisticated phishing attempts
- Works best with common phishing techniques

**Always use common sense and verify websites independently!**

## 🤝 Contributing

Found a bug or want to improve detection? Contributions are welcome!

## 📝 License

This project is provided as-is for educational and personal use.

## 🙏 Acknowledgments

Designed to protect users from increasingly sophisticated phishing and scam attempts. Stay safe online! 🛡️

---

**Made with ❤️ for a safer internet**
