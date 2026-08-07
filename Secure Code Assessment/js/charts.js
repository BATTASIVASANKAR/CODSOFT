/**
 * SECURE CODE ASSESSMENT TOOL - CHART VISUALIZATION MODULE
 * Uses Chart.js for rendering Severity & OWASP vulnerability distributions.
 */

window.SASTCharts = (function () {
  let severityChartInstance = null;
  let owaspChartInstance = null;

  function renderSeverityChart(canvasId, severityCounts) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    if (severityChartInstance) {
      severityChartInstance.destroy();
    }

    const data = {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [
          severityCounts.critical || 0,
          severityCounts.high || 0,
          severityCounts.medium || 0,
          severityCounts.low || 0
        ],
        backgroundColor: [
          '#ef4444', // Critical Red
          '#f97316', // High Orange
          '#eab308', // Medium Yellow
          '#3b82f6'  // Low Blue
        ],
        borderWidth: 2,
        borderColor: '#0f172a'
      }]
    };

    severityChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: data,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#94a3b8',
              font: { family: 'Inter', size: 12 }
            }
          },
          tooltip: {
            backgroundColor: '#1e293b',
            titleColor: '#f8fafc',
            bodyColor: '#f8fafc'
          }
        },
        cutout: '70%'
      }
    });
  }

  function renderOWASPChart(canvasId, owaspBreakdown) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    if (owaspChartInstance) {
      owaspChartInstance.destroy();
    }

    const labels = Object.keys(owaspBreakdown).map(key => {
      // Shorten label for clean chart presentation (e.g. "A03: Injection")
      return key.length > 25 ? key.substring(0, 22) + '...' : key;
    });
    const values = Object.values(owaspBreakdown);

    owaspChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels.length > 0 ? labels : ['No Findings'],
        datasets: [{
          label: 'Vulnerability Count',
          data: values.length > 0 ? values : [0],
          backgroundColor: '#00f2fe',
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: '#94a3b8', font: { family: 'Inter', size: 11 } },
            grid: { color: 'rgba(255, 255, 255, 0.05)' }
          },
          y: {
            beginAtZero: true,
            ticks: { color: '#94a3b8', stepSize: 1 },
            grid: { color: 'rgba(255, 255, 255, 0.05)' }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#1e293b',
            titleColor: '#f8fafc',
            bodyColor: '#f8fafc'
          }
        }
      }
    });
  }

  return {
    renderSeverityChart: renderSeverityChart,
    renderOWASPChart: renderOWASPChart
  };

})();
