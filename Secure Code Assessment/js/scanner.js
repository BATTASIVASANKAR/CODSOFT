/**
 * SECURE CODE ASSESSMENT TOOL - STATIC SECURITY ANALYSIS SCANNER ENGINE
 */

window.SASTScanner = (function () {
  
  /**
   * Helper to detect file extension / language
   */
  function detectLanguage(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    switch (ext) {
      case 'py': return 'py';
      case 'js':
      case 'jsx':
      case 'ts':
      case 'tsx': return 'js';
      case 'java': return 'java';
      case 'cpp':
      case 'c':
      case 'h':
      case 'hpp': return 'cpp';
      case 'php': return 'php';
      default: return 'js'; // Default fallback
    }
  }

  /**
   * Scan code line by line using SAST_RULES
   */
  function analyzeCode(code, filename = "uploaded_file.txt") {
    const lang = detectLanguage(filename);
    const lines = code.split(/\r?\n/);
    const findings = [];
    const rules = window.SAST_RULES || [];

    // Filter rules relevant to detected language or universal rules
    const applicableRules = rules.filter(rule => 
      rule.languages.includes(lang) || rule.languages.includes('*')
    );

    lines.forEach((lineText, index) => {
      const lineNumber = index + 1;
      const trimmedLine = lineText.trim();
      
      // Skip empty lines or standard non-vulnerable comments
      if (!trimmedLine || trimmedLine.startsWith('//') || trimmedLine.startsWith('#') || trimmedLine.startsWith('/*')) {
        return;
      }

      applicableRules.forEach(rule => {
        if (rule.pattern.test(lineText)) {
          // Avoid duplicate findings on same line for same rule
          const alreadyMatched = findings.some(f => f.lineNumber === lineNumber && f.ruleId === rule.id);
          if (!alreadyMatched) {
            findings.push({
              id: 'FINDING_' + Math.random().toString(36).substr(2, 9),
              ruleId: rule.id,
              title: rule.name,
              category: rule.category,
              owasp: rule.owasp,
              severity: rule.severity,
              lineNumber: lineNumber,
              snippet: trimmedLine,
              description: rule.description,
              risk: rule.risk,
              remediation: rule.remediation,
              secureExample: rule.secureExample,
              filename: filename
            });
          }
        }
      });
    });

    // Calculate metrics
    const metrics = calculateMetrics(findings, lines.length);

    const scanResult = {
      filename: filename,
      language: lang,
      totalLines: lines.length,
      timestamp: new Date().toLocaleString(),
      findings: findings,
      metrics: metrics,
      code: code
    };

    // Store latest scan result in localStorage for report generation
    try {
      localStorage.setItem('sast_latest_report', JSON.stringify(scanResult));
    } catch (e) {
      console.warn('LocalStorage save error:', e);
    }

    return scanResult;
  }

  /**
   * Calculate severity counts, OWASP counts, and overall Security Grade
   */
  function calculateMetrics(findings, totalLines) {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: findings.length
    };

    const owaspBreakdown = {};

    findings.forEach(f => {
      const sev = f.severity.toLowerCase();
      if (counts[sev] !== undefined) {
        counts[sev]++;
      }

      // OWASP Breakdown
      const categoryKey = f.owasp || "Unmapped Vulnerabilities";
      owaspBreakdown[categoryKey] = (owaspBreakdown[categoryKey] || 0) + 1;
    });

    // Deduct points based on CVSS severity weight
    let penalty = (counts.critical * 25) + (counts.high * 15) + (counts.medium * 8) + (counts.low * 3);
    let score = Math.max(0, 100 - penalty);

    let grade = 'A+';
    if (score >= 90) grade = 'A';
    else if (score >= 75) grade = 'B';
    else if (score >= 60) grade = 'C';
    else if (score >= 40) grade = 'D';
    else grade = 'F';

    return {
      severityCounts: counts,
      owaspBreakdown: owaspBreakdown,
      securityScore: score,
      grade: grade
    };
  }

  return {
    analyzeCode: analyzeCode,
    detectLanguage: detectLanguage
  };

})();
