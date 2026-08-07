/**
 * SECURE CODE ASSESSMENT TOOL - APPLICATION CONTROLLER
 * Coordinates Theme Toggle, Navigation, Drag & Drop Uploads, Sample Files, UI Rendering, and Filters.
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initMobileNav();
  initScannerPage();
  initReportPage();
  initContactForm();
});

/* ==========================================================================
   1. THEME SWITCHER (DARK / LIGHT MODE)
   ========================================================================== */
function initTheme() {
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const savedTheme = localStorage.getItem('sast_theme') || 'dark';
  
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('sast_theme', newTheme);
      updateThemeIcon(newTheme);
    });
  }
}

function updateThemeIcon(theme) {
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  if (themeToggleBtn) {
    themeToggleBtn.innerHTML = theme === 'dark' 
      ? '<i class="fa-solid me-0 fa-sun" title="Switch to Light Mode"></i>' 
      : '<i class="fa-solid me-0 fa-moon" title="Switch to Dark Mode"></i>';
  }
}

/* ==========================================================================
   2. MOBILE NAVIGATION
   ========================================================================== */
function initMobileNav() {
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const navLinks = document.getElementById('navLinks');

  if (mobileMenuBtn && navLinks) {
    mobileMenuBtn.addEventListener('click', () => {
      navLinks.classList.toggle('active');
    });
  }
}

/* ==========================================================================
   3. SCANNER PAGE LOGIC (Uploader, Samples, Live Scanner)
   ========================================================================== */
let currentCode = "";
let currentFilename = "vulnerable_sample.py";

function initScannerPage() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const codeEditor = document.getElementById('codeEditor');
  const runScanBtn = document.getElementById('runScanBtn');
  const sampleChips = document.querySelectorAll('.sample-chip');

  if (!codeEditor) return; // Not on scanner page

  // Load initial sample Python file if editor is empty
  if (!codeEditor.value) {
    loadSampleFile('vulnerable_sample.py');
  }

  // File Input Upload
  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) handleFile(file);
    });

    // Drag & Drop
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
      }, false);
    });

    dropzone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const file = dt.files[0];
      if (file) handleFile(file);
    });
  }

  // Sample Chips
  sampleChips.forEach(chip => {
    chip.addEventListener('click', () => {
      sampleChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      const sampleFile = chip.getAttribute('data-sample');
      loadSampleFile(sampleFile);
    });
  });

  // Run SAST Scan Button
  if (runScanBtn) {
    runScanBtn.addEventListener('click', () => {
      executeScan();
    });
  }
}

function handleFile(file) {
  const reader = new FileReader();
  reader.onload = function (e) {
    currentCode = e.target.result;
    currentFilename = file.name;
    const codeEditor = document.getElementById('codeEditor');
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    
    if (codeEditor) codeEditor.value = currentCode;
    if (fileNameDisplay) fileNameDisplay.textContent = currentFilename;

    executeScan();
  };
  reader.readAsText(file);
}

function loadSampleFile(sampleName) {
  const samplePath = `assets/samples/${sampleName}`;
  fetch(samplePath)
    .then(res => {
      if (!res.ok) throw new Error("Sample fetch failed");
      return res.text();
    })
    .then(code => {
      currentCode = code;
      currentFilename = sampleName;
      const codeEditor = document.getElementById('codeEditor');
      const fileNameDisplay = document.getElementById('fileNameDisplay');

      if (codeEditor) codeEditor.value = currentCode;
      if (fileNameDisplay) fileNameDisplay.textContent = currentFilename;

      executeScan();
    })
    .catch(err => {
      console.warn("Sample load warning:", err);
    });
}

function executeScan() {
  const codeEditor = document.getElementById('codeEditor');
  if (!codeEditor) return;

  const code = codeEditor.value;
  const fileNameDisplay = document.getElementById('fileNameDisplay');
  const filename = fileNameDisplay ? fileNameDisplay.textContent : 'code_snippet.txt';

  if (!code.trim()) {
    alert("Please upload or enter source code to scan.");
    return;
  }

  // Execute SAST Scanner Engine
  const result = window.SASTScanner.analyzeCode(code, filename);
  renderScannerFindings(result);
}

function renderScannerFindings(result) {
  const findingsListContainer = document.getElementById('findingsList');
  const totalFindingsBadge = document.getElementById('totalFindingsBadge');
  const scanStatusBadge = document.getElementById('scanStatusBadge');

  if (!findingsListContainer) return;

  const findings = result.findings;

  if (totalFindingsBadge) totalFindingsBadge.textContent = findings.length;
  if (scanStatusBadge) {
    scanStatusBadge.textContent = findings.length > 0 ? `${findings.length} Security Risks Found` : "Code Secure";
    scanStatusBadge.className = `badge ${findings.length > 0 ? 'badge-critical' : 'badge-info'}`;
  }

  if (findings.length === 0) {
    findingsListContainer.innerHTML = `
      <div class="scanner-empty-state">
        <i class="fa-solid fa-shield-halved" style="color: var(--sev-info);"></i>
        <h3>No Security Vulnerabilities Detected</h3>
        <p>Source code passed static analysis checks without matching high-risk patterns.</p>
      </div>
    `;
    return;
  }

  let html = '';
  findings.forEach((f, idx) => {
    html += `
      <div class="finding-card ${f.severity.toLowerCase()}" onclick="highlightLineInEditor(${f.lineNumber})">
        <div class="finding-card-header">
          <span class="finding-title">${escapeHTML(f.title)}</span>
          <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
        </div>
        <div class="finding-line"><i class="fa-solid fa-code-commit"></i> Line ${f.lineNumber} | ${escapeHTML(f.category)}</div>
        <div class="finding-snippet">Line ${f.lineNumber}: ${escapeHTML(f.snippet)}</div>
      </div>
    `;
  });

  findingsListContainer.innerHTML = html;
}

function highlightLineInEditor(lineNumber) {
  const codeEditor = document.getElementById('codeEditor');
  if (!codeEditor) return;

  const lines = codeEditor.value.split('\n');
  let pos = 0;
  for (let i = 0; i < lineNumber - 1 && i < lines.length; i++) {
    pos += lines[i].length + 1; // +1 for \n
  }

  codeEditor.focus();
  codeEditor.setSelectionRange(pos, pos + (lines[lineNumber - 1] ? lines[lineNumber - 1].length : 0));
}

/* ==========================================================================
   4. REPORT PAGE LOGIC (Charts, Metric Cards, Accordion, Filters, PDF)
   ========================================================================== */
function initReportPage() {
  const reportContainer = document.getElementById('reportViewContainer');
  if (!reportContainer) return; // Not on report page

  let storedData = localStorage.getItem('sast_latest_report');
  let scanResult;

  if (storedData) {
    try {
      scanResult = JSON.parse(storedData);
    } catch (e) {
      scanResult = null;
    }
  }

  // Fallback if no scan has been executed yet: run scan on default Python sample
  if (!scanResult) {
    fetch('assets/samples/vulnerable_sample.py')
      .then(res => res.text())
      .then(code => {
        scanResult = window.SASTScanner.analyzeCode(code, 'vulnerable_sample.py');
        renderReportPageData(scanResult);
      });
  } else {
    renderReportPageData(scanResult);
  }
}

function renderReportPageData(scanResult) {
  if (!scanResult) return;

  // Header & Metadata
  const reportFilename = document.getElementById('reportFilename');
  const reportDate = document.getElementById('reportDate');
  const scoreGrade = document.getElementById('scoreGrade');
  const scoreNumber = document.getElementById('scoreNumber');
  const totalVulnsMetric = document.getElementById('totalVulnsMetric');
  const criticalCountMetric = document.getElementById('criticalCountMetric');
  const highCountMetric = document.getElementById('highCountMetric');
  const totalLinesMetric = document.getElementById('totalLinesMetric');

  if (reportFilename) reportFilename.textContent = scanResult.filename;
  if (reportDate) reportDate.textContent = scanResult.timestamp;
  if (scoreGrade) {
    scoreGrade.textContent = scanResult.metrics.grade;
    scoreGrade.className = `score-grade grade-${scanResult.metrics.grade.charAt(0)}`;
  }
  if (scoreNumber) scoreNumber.textContent = `${scanResult.metrics.securityScore}/100 Score`;
  if (totalVulnsMetric) totalVulnsMetric.textContent = scanResult.metrics.severityCounts.total;
  if (criticalCountMetric) criticalCountMetric.textContent = scanResult.metrics.severityCounts.critical;
  if (highCountMetric) highCountMetric.textContent = scanResult.metrics.severityCounts.high;
  if (totalLinesMetric) totalLinesMetric.textContent = scanResult.totalLines;

  // Render Charts
  if (window.SASTCharts) {
    window.SASTCharts.renderSeverityChart('severityChart', scanResult.metrics.severityCounts);
    window.SASTCharts.renderOWASPChart('owaspChart', scanResult.metrics.owaspBreakdown);
  }

  // Render Vulnerabilities Table Accordion
  renderVulnerabilitiesAccordion(scanResult.findings);

  // Setup Search & Filter Listeners
  const searchInput = document.getElementById('searchVulnInput');
  const severityFilter = document.getElementById('severityFilterSelect');

  if (searchInput) {
    searchInput.addEventListener('input', () => filterVulnerabilities(scanResult.findings));
  }
  if (severityFilter) {
    severityFilter.addEventListener('change', () => filterVulnerabilities(scanResult.findings));
  }

  // PDF Export CTA
  const downloadPdfBtn = document.getElementById('downloadPdfBtn');
  if (downloadPdfBtn) {
    downloadPdfBtn.addEventListener('click', () => {
      if (window.SASTPDFGenerator) {
        window.SASTPDFGenerator.downloadPDF(scanResult);
      }
    });
  }
}

function renderVulnerabilitiesAccordion(findings) {
  const container = document.getElementById('vulnerabilitiesAccordion');
  if (!container) return;

  if (findings.length === 0) {
    container.innerHTML = `
      <div class="glass-card text-center" style="padding: 3rem;">
        <i class="fa-solid fa-circle-check" style="font-size: 3rem; color: var(--sev-info); margin-bottom: 1rem;"></i>
        <h3>Zero Vulnerabilities Found</h3>
        <p style="color: var(--text-secondary);">The target source code meets static security compliance criteria.</p>
      </div>
    `;
    return;
  }

  let html = '';
  findings.forEach((f, idx) => {
    html += `
      <div class="vuln-item" id="vuln-item-${idx}">
        <div class="vuln-item-header" onclick="toggleVulnAccordion(${idx})">
          <div class="vuln-item-title-area">
            <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
            <div>
              <div class="vuln-title">${escapeHTML(f.title)}</div>
              <div class="vuln-meta">${escapeHTML(f.category)} | Line ${f.lineNumber} | ${escapeHTML(f.owasp || 'OWASP Unmapped')}</div>
            </div>
          </div>
          <i class="fa-solid fa-chevron-down accordion-icon"></i>
        </div>
        <div class="vuln-item-body">
          <div class="vuln-details-grid">
            <div class="detail-block">
              <h5>Description</h5>
              <p>${escapeHTML(f.description)}</p>
            </div>
            <div class="detail-block">
              <h5>Business Risk & Impact</h5>
              <p>${escapeHTML(f.risk)}</p>
            </div>
          </div>
          
          <div class="code-box-wrapper">
            <div class="code-box-label"><i class="fa-solid fa-triangle-exclamation" style="color: var(--sev-critical);"></i> Vulnerable Snippet (Line ${f.lineNumber})</div>
            <div class="code-box-snippet">${escapeHTML(f.snippet)}</div>
          </div>

          <div class="code-box-wrapper" style="margin-top: 1.25rem;">
            <div class="code-box-label"><i class="fa-solid fa-shield" style="color: var(--sev-info);"></i> Recommended Fix & Secure Code Example</div>
            <p style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 0.5rem;">${escapeHTML(f.remediation)}</p>
            <div class="code-box-fix"><pre style="margin: 0; white-space: pre-wrap;">${escapeHTML(f.secureExample)}</pre></div>
          </div>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

function toggleVulnAccordion(idx) {
  const item = document.getElementById(`vuln-item-${idx}`);
  if (item) {
    item.classList.toggle('expanded');
  }
}

function filterVulnerabilities(allFindings) {
  const searchInput = document.getElementById('searchVulnInput');
  const severityFilter = document.getElementById('severityFilterSelect');

  const query = searchInput ? searchInput.value.toLowerCase() : '';
  const selectedSev = severityFilter ? severityFilter.value : 'ALL';

  const filtered = allFindings.filter(f => {
    const matchesQuery = f.title.toLowerCase().includes(query) || 
                         f.description.toLowerCase().includes(query) ||
                         f.category.toLowerCase().includes(query) ||
                         f.snippet.toLowerCase().includes(query);
    const matchesSev = selectedSev === 'ALL' || f.severity.toUpperCase() === selectedSev.toUpperCase();
    return matchesQuery && matchesSev;
  });

  renderVulnerabilitiesAccordion(filtered);
}

/* ==========================================================================
   5. CONTACT FORM
   ========================================================================== */
function initContactForm() {
  const contactForm = document.getElementById('contactForm');
  if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const statusMessage = document.getElementById('contactStatusMessage');
      if (statusMessage) {
        statusMessage.style.display = 'block';
        statusMessage.className = 'glass-card';
        statusMessage.style.borderColor = 'var(--sev-info)';
        statusMessage.innerHTML = `<i class="fa-solid fa-circle-check" style="color: var(--sev-info);"></i> Thank you! Your message has been sent successfully.`;
        contactForm.reset();
      }
    });
  }
}

function escapeHTML(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
