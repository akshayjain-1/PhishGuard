# PhishGuard

## Overview
PhishGuard is a Python-based tool to detect phishing emails by analyzing email headers, URLs, and other common indicators. It helps identify malicious elements and simplifies email analysis.

## Features
- **Email Parsing**: Supports parsing of .eml files to extract relevant information.
- **Sender Validation**: Checks sender's domain using SPF, DKIM, and DMARC protocols.
- **Header Analysis**: Identifies anomalies in email headers that may indicate phishing attempts.
- **URL Extraction and Analysis**: Extracts URLs from the email body and checks them against VirusTotal for malicious content.
- **Attachment Analysis**: Checks for attachments, hashes them, and analyzes their content using VirusTotal.
- **QR Code Detection**: Scans for QR codes in the email body and attachments, extracting any URLs present.
- **Fake Invoice Detection**: Identifies potential fake invoice scams based on email content.
- **Comprehensive Reporting**: Generates a detailed report summarizing all findings.

## Prerequisites

Before running the application, ensure you have the following dependencies installed:

- **ZBar**: This library is required for barcode and QR code decoding. You can install it using your package manager:

  - **For Ubuntu/Debian**:
    ```bash
    sudo apt-get install libzbar0
    ```

  - **For Fedora**:
    ```bash
    sudo dnf install zbar
    ```

  - **For macOS**:
    ```bash
    brew install zbar
    ```

## Installation
1. Install Poetry: 
    ```bash 
    pip install poetry
2. Clone the repository:
   ```bash
   git clone https://github.com/akshayjain-1/PhishGuard.git
3. Navigate to the project directory:
    ```bash
    cd PhishGuard
4. Install dependencies:
    ```bash
    poetry install
5. Activate the virtual environment
    ```bash
    poetry shell
6. Set up environment variables for API keys:
    ```bash
    export VIRUSTOTAL_API_KEY="your_virustotal_api_key"

## Usage
```poetry run python phishguard.py ```
1. Follow the prompts to provide the full path of the saved email file.

## Output

The program will generate a detailed report summarizing the analysis results, including:
- Sender validation results
- Header anomalies
- URL analysis
- Attachment analysis
- QR code URL analysis
- Detection of phishing indicators and fake invoices

## Logging
All activities and errors are logged to `email_analyzer.log` for further investigation.

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.
