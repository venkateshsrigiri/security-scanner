
---

# 🔹 2. BACKEND README (Spring Boot)

```md
#  Smart Security Scanner – Backend

This is the backend service for the Smart Security Scanner. It processes files and URLs to detect potential security threats such as phishing, malicious links, and sensitive data exposure.

##  Live API
 https://security-scanner-qnes.onrender.com

---

## 🧩 Features

- File scanning (PDF, documents)
- URL security analysis
- Suspicious link detection
- Sensitive data detection (API keys, passwords, etc.)
- Risk scoring system
- Generates structured security reports

---

##  Tech Stack

- Java
- Spring Boot
- Apache Tika (text extraction)
- Apache PDFBox (PDF analysis)
- REST APIs

---


---

## ⚙️ How It Works

1. Receives file or URL from frontend
2. Extracts content (text, links, metadata)
3. Runs multiple checks:
   - Malicious link detection
   - Phishing indicators
   - Sensitive data patterns
4. Assigns a risk score
5. Returns a detailed report

---

## 🖥️ Running Locally

```bash
git clone https://github.com/venkateshsrigiri/security-scanner.git
cd backend-repo
mvn clean install
mvn spring-boot:run

## ⚙️ API Endpoints

Base URL:
http://localhost:8080/scan

---

### 🔹 Scan File

Endpoint:
POST /scan/file

Description:
Uploads a file and scans it for potential security threats.

Request (Multipart Form Data):
file: <uploaded file>

Response (JSON):
{
  "fileName": "test.pdf",
  "riskScore": 75,
  "status": "Suspicious",
  "issues": [
    "Contains suspicious links",
    "Possible sensitive data detected"
  ]
}

---

### 🔹 Scan URL

Endpoint:
POST /scan/url

Description:
Analyzes a given URL for phishing, malicious content, and adult content.

Request (JSON):
{
  "url": "https://paypal.com.signin.verify-user.com"
}

Response (JSON):
{
  "url": "https://paypal.com.signin.verify-user.com",
  "riskScore": 60,
  "status": "Warning",
  "issues": [
    "Suspicious domain",
    "Contains login form"
  ]
}

---

### 🔹 Health Check

Endpoint:
GET /health

Description:
Checks if the backend service is running.

Response (JSON):
{
  "status": "UP"
}
