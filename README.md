# Phishing Link Scanner

A comprehensive Python-based phishing link scanner that uses modern technologies and machine learning to detect potential phishing threats.

## Features

- SSL/TLS certificate validation
- Domain reputation checking
- URL structure analysis
- Machine learning-based classification
- Redirect chain analysis
- Risk scoring system
- WHOIS information analysis

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd phishing-scanner
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the scanner:
```bash
python phishing_scanner.py
```

The program will prompt you to enter a URL to scan. It will then perform a comprehensive analysis and display the results, including:

- Risk score and level
- SSL certificate information
- Domain registration details
- URL feature analysis
- Redirect chain information

## How It Works

The scanner uses multiple techniques to detect potential phishing threats:

1. **SSL Certificate Analysis**: Checks for valid SSL certificates and their expiration dates
2. **Domain Analysis**: Examines domain age, registration details, and WHOIS information
3. **URL Feature Analysis**: Analyzes URL structure, length, and suspicious patterns
4. **Redirect Chain Analysis**: Tracks and analyzes URL redirects
5. **Machine Learning**: Uses a Random Forest classifier to identify suspicious patterns

## Risk Scoring

The scanner calculates a risk score (0-100) based on multiple factors:

- SSL certificate validity (30 points)
- Domain age (20 points)
- Suspicious keywords (15 points)
- URL structure anomalies (10 points each)
- Suspicious redirects (15 points)

Risk levels are categorized as:
- Low: 0-30
- Medium: 31-70
- High: 71-100

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Always use it responsibly and in accordance with applicable laws and regulations. 