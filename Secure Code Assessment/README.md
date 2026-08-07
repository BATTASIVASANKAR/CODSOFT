# 🛡️ Secure Code Assessment Tool

> **Cyber Security Internship Project**  
> A professional, interactive web application for **Static Application Security Testing (SAST)** and automated vulnerability assessment of source code mapped to **OWASP Top 10 (2021)** standards.

---

## 📌 Project Overview

The **Secure Code Assessment Tool** is a web-based static code analysis platform designed to audit source code for security vulnerabilities before deployment. Built as part of a Cyber Security Internship, it performs client-side pattern matching, AST line parsing, and rule-based evaluation across multiple programming languages including **Python (`.py`)**, **JavaScript (`.js`)**, **Java (`.java`)**, **C/C++ (`.cpp`)**, and **PHP (`.php`)**.

The application flags critical vulnerabilities such as **SQL Injection**, **Cross-Site Scripting (XSS)**, **OS Command Injection**, **Hardcoded Secrets**, **Weak Password Hashing**, **Path Traversal**, and **Disabled TLS**, and generates an **audit-ready downloadable PDF Vulnerability Assessment Report**.

---

## ✨ Features

- ** Modern Cybersecurity Responsive UI**: Obsidian dark mode with glowing cyan/violet accents, glassmorphism cards, and dark/light theme switcher.
- ** Multilingual SAST Engine**: Static code review for Python, JavaScript/Node.js, Java, C/C++, and PHP.
- ** Drag & Drop Upload + Sample Selector**: Upload custom source code files or pick pre-loaded vulnerable code samples (.py, .js, .java, .cpp, .php) for single-click demo testing.
- ** Code Viewer with Line Highlights**: Displays target code with line numbers and interactive line callouts for detected security flaws.
- ** OWASP Top 10 (2021) Mapping**: Automatically maps every finding to official OWASP Top 10 categories (A01: Broken Access Control, A02: Cryptographic Failures, A03: Injection, A05: Security Misconfiguration, A07: Auth Failures).
- ** Dynamic Charts & Metrics (Chart.js)**:
  - **Donut Chart**: Vulnerability distribution by Severity (Critical, High, Medium, Low).
  - **Bar Chart**: Breakdown by OWASP Top 10 categories.
  - **Security Score Meter**: Calculated security grade (A+ through F) and weighted CVSS score (0-100).
- ** Downloadable PDF Report Generator**: Generates formatted multi-page PDF vulnerability reports via `html2pdf.js` with executive summary, metadata, risk descriptions, and secure fix code examples.
- ** Detailed Documentation & About Pages**: Explains SAST vs. DAST testing, severity rating matrix, and rule definitions.
- ** Filterable Findings Accordion**: Search vulnerability titles by keyword or filter by severity level.

---

## 🛠️ Technologies Used

- **Frontend Core**: HTML5, CSS3, Vanilla JavaScript (ES6+)
- **Styling & Theme**: Vanilla CSS (CSS Variables, Flexbox/Grid, Glassmorphism, Responsive Breakpoints)
- **Data Visualization**: [Chart.js v4.4.0](https://www.chartjs.org/)
- **PDF Generation**: [html2pdf.js v0.10.1](https://rawgit.com/eKoopmans/html2pdf/master/dist/html2pdf.bundle.min.js)
- **Icons & Typography**: FontAwesome 6.4.0, Google Fonts (*Inter*, *Outfit*, *JetBrains Mono*)

---

## 📁 Folder Structure

```
Secure-Code-Assessment/
│── assets/
│   ├── images/              # Project diagrams & screenshots placeholder
│   └── samples/             # Pre-loaded vulnerable source code files
│       ├── vulnerable_sample.py
│       ├── vulnerable_sample.js
│       ├── vulnerable_sample.java
│       ├── vulnerable_sample.cpp
│       └── vulnerable_sample.php
│── css/
│   ├── style.css            # Master cyber design system, variables, dark/light modes
│   ├── scanner.css          # Code viewer, dropzone, severity tags, editor styles
│   └── report.css           # Executive summary report styles, metric cards, charts
│── js/
│   ├── rules.js             # SAST Security Rule Engine (Regex, OWASP mappings, fixes)
│   ├── scanner.js           # Multi-language static analysis parser & line highlighter
│   ├── charts.js            # Chart.js visualization module (Donut & Bar charts)
│   ├── pdf-generator.js     # PDF report export module via html2pdf.js
│   └── app.js               # Theme toggle, drag-drop events, sample switcher, filters
│── uploads/                 # Storage placeholder for uploaded file metadata
│── reports/                 # Saved report templates reference
│── index.html               # Dashboard homepage with project overview & CTA
│── scanner.html             # Interactive SAST code scanner & split-screen viewer
│── report.html              # Vulnerability assessment report & PDF exporter
│── about.html               # SAST methodology, SAST vs DAST comparison, internship scope
│── documentation.html       # Step-by-step user guide & OWASP Top 10 mapping table
│── contact.html             # Professional contact form & intern profile
└── README.md                # GitHub project documentation
```

---

## 🚀 Installation & Usage

### 1. Quick Local Execution (Zero Backend Setup Needed)
Since this is a client-side application, no server or Node.js environment is required to run the tool.

1. Clone or download the repository:
   ```bash
   git clone https://github.com/your-username/Secure-Code-Assessment.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Secure-Code-Assessment
   ```
3. Open `index.html` in any modern web browser (Chrome, Firefox, Edge, Safari):
   ```bash
   # On Windows (PowerShell):
   Start-Process index.html
   ```

---

## 🎯 How to Perform a Code Assessment

1. **Launch Scanner**: Click on **"Code Scanner"** in the navigation bar.
2. **Choose Source Code**:
   - Drag and drop a file (`.py`, `.js`, `.java`, `.cpp`, `.php`).
   - Or click one of the sample buttons (e.g. `Python (.py)`) to load vulnerable code instantly.
3. **Execute Analysis**: Click **"Run SAST Scan"**.
4. **Review Findings**:
   - View flagged lines in the code panel.
   - Click findings in the right panel to jump to exact line numbers.
5. **Generate & Download PDF**:
   - Go to **"Vulnerability Report"**.
   - Review severity donut charts and OWASP breakdown.
   - Click **"Download PDF Report"** to export an executive audit document.

---

## 🖼️ Sample Screenshots

| Page | Description |
| :--- | :--- |
| **Dashboard (`index.html`)** | Modern cyber-themed homepage featuring project metrics, live scanner preview, and feature grid. |
| **Code Scanner (`scanner.html`)** | Split-screen code editor, sample selector chips, drag-and-drop dropzone, and live findings panel. |
| **Vulnerability Report (`report.html`)** | Security grade circle meter, Chart.js severity graphs, filterable accordion, and PDF export CTA. |

---

## 🔬 Vulnerabilities Detected

| Vulnerability Category | OWASP Mapping | Default Severity |
| :--- | :--- | :--- |
| **Hardcoded Secrets & Passwords** | A07:2021 - Identification & Auth Failures | `CRITICAL` |
| **SQL Injection (SQLi)** | A03:2021 - Injection | `CRITICAL` |
| **OS Command Injection** | A03:2021 - Injection | `CRITICAL` |
| **Cross-Site Scripting (XSS)** | A03:2021 - Injection | `HIGH` |
| **Path Traversal / Arbitrary File Read** | A01:2021 - Broken Access Control | `HIGH` |
| **Weak Hashing Algorithms (MD5/SHA1)** | A02:2021 - Cryptographic Failures | `HIGH` |
| **Unsafe Deserialization** | A08:2021 - Software & Data Integrity Failures | `HIGH` |
| **Debug Mode Active in Production** | A05:2021 - Security Misconfiguration | `MEDIUM` |
| **Sensitive Info Logged to Console** | A09:2021 - Security Logging Failures | `LOW` |

---

## 🔮 Future Improvements

- Add support for AST (Abstract Syntax Tree) parsing engines for full semantic context matching.
- Expand rule sets for additional languages (C#, Go, Ruby, Rust, Kotlin).
- CI/CD GitHub Actions integration for automated PR security checks.
- Export findings in SARIF (Static Analysis Results Interchange Format) standard.

---

## 👨‍💻 Author

- **Role**: Cyber Security Intern
- **Project**: Secure Code Assessment Tool
- **Track**: Secure Software Development & Vulnerability Management
- **Repository**: [GitHub Repository](https://github.com)
