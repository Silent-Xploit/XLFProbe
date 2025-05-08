# XLF (Local File & XSS Probe)

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

XLF is a powerful and user-friendly security testing tool designed to detect Local File Inclusion (LFI) and Cross-Site Scripting (XSS) vulnerabilities in web applications.

## Features

- 🔍 **LFI Scanner**
  - Custom payload support
  - Advanced pattern matching
  - Multi-platform file path detection
  - False positive reduction system

- 🎯 **XSS Scanner**
  - Support for multiple XSS vectors
  - Smart payload validation
  - Context-aware detection
  - Advanced filter bypass detection

- 📊 **HTML Reports**
  - Detailed scan results
  - Clean and organized layout
  - Timestamp-based report generation
  - Easy-to-read vulnerability details

- 🛠 **Additional Features**
  - Colorful CLI interface
  - Bulk URL scanning
  - Auto-update system
  - Custom payload file support
  - Response analysis and validation

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Silent-Xploit/XLFProbe.git
cd XLFProbe
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the tool:
```bash
python3 XLF.py
```

2. Choose scanning mode:
   - LFI Scanner (Option 1)
   - XSS Scanner (Option 2)

3. Select scan type:
   - Single URL
   - Bulk Scan

4. Provide required inputs:
   - Target URL(s)
   - Payload file path

### Payload Files

Create custom payload files for both LFI and XSS scans. Example formats:

- `lfi_payloads.txt`:
```text
../../../../../etc/passwd
../../../../../../etc/shadow
../../../../../../../windows/win.ini
```

- `xss_payloads.txt`:
```text
<script>alert('XSS');</script>
<img src="x" onerror="alert('XSS');">
<svg onload="alert('XSS');">
```

## Screenshots

(Add your tool screenshots here)

## Output

The tool generates two types of output:
1. Real-time CLI feedback with color-coded results
2. Detailed HTML reports in the `reports` directory

## Auto-Update

The tool includes an auto-update feature (Option 3) that:
- Checks for new versions
- Downloads updates automatically
- Maintains your configuration files

## Contributing

1. Fork the repository
2. Create your feature branch:
```bash
git checkout -b feature/AmazingFeature
```
3. Commit your changes:
```bash
git commit -m 'Add some AmazingFeature'
```
4. Push to the branch:
```bash
git push origin feature/AmazingFeature
```
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- det0x

## Disclaimer

This tool is for educational and testing purposes only. Always obtain proper authorization before testing any websites or applications. The author is not responsible for any misuse or damage caused by this tool.

## Acknowledgments

- Python Security Community
- Open Source Contributors
- Security Researchers worldwide