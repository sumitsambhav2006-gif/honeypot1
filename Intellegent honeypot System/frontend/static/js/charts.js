// ==============================================================================
// IHTIP - Chart.js Visualizations & Threat Graphics
// ==============================================================================

const CyberCharts = {
  // Common Dark Cyber Theme Options
  defaultOptions: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#94a3b8',
          font: { family: "'Inter', sans-serif", size: 12 }
        }
      },
      tooltip: {
        backgroundColor: '#0f172a',
        borderColor: '#00e5ff',
        borderWidth: 1,
        titleColor: '#00e5ff',
        bodyColor: '#f8fafc',
        bodyFont: { family: "'JetBrains Mono', monospace" }
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: '#64748b', font: { family: "'JetBrains Mono', monospace", size: 10 } }
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: '#64748b', font: { family: "'JetBrains Mono', monospace", size: 10 } }
      }
    }
  },

  // 1. Attack Timeline Line Chart
  renderTrendChart(ctx, labels, data) {
    const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, 'rgba(0, 229, 255, 0.35)');
    gradient.addColorStop(1, 'rgba(0, 229, 255, 0.0)');

    return new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Attacks Detected',
          data: data,
          borderColor: '#00e5ff',
          backgroundColor: gradient,
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointBackgroundColor: '#00e5ff',
          pointBorderColor: '#0a0e17',
          pointRadius: 4,
          pointHoverRadius: 6
        }]
      },
      options: this.defaultOptions
    });
  },

  // 2. Risk Distribution Donut Chart
  renderRiskDonut(ctx, riskCounts) {
    return new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Low (0-29)', 'Medium (30-59)', 'High (60-79)', 'Critical (80-100)'],
        datasets: [{
          data: [
            riskCounts.Low || 0,
            riskCounts.Medium || 0,
            riskCounts.High || 0,
            riskCounts.Critical || 0
          ],
          backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444'],
          borderColor: '#111827',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#94a3b8', font: { family: "'Inter', sans-serif", size: 11 } }
          }
        },
        cutout: '70%'
      }
    });
  },

  // 3. Command Category Horizontal Bar Chart
  renderCommandCategories(ctx, categories, counts) {
    return new Chart(ctx, {
      type: 'bar',
      data: {
        labels: categories,
        datasets: [{
          label: 'Commands Logged',
          data: counts,
          backgroundColor: 'rgba(0, 255, 157, 0.65)',
          borderColor: '#00ff9d',
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        ...this.defaultOptions,
        indexAxis: 'y'
      }
    });
  },

  // 4. Country Distribution Bar Chart
  renderCountryBar(ctx, countries, counts) {
    return new Chart(ctx, {
      type: 'bar',
      data: {
        labels: countries,
        datasets: [{
          label: 'Total Attacks by Country',
          data: counts,
          backgroundColor: 'rgba(56, 189, 248, 0.7)',
          borderColor: '#38bdf8',
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: this.defaultOptions
    });
  }
};

