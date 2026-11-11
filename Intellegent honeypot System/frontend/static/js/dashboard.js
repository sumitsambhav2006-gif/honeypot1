// ==============================================================================
// IHTIP - Dashboard Controller
// ==============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initLiveClock();
  loadDashboardData();
  // Auto refresh every 5 seconds for real-time demo responsiveness
  setInterval(loadDashboardData, 5000);
});

function initLiveClock() {
  const clockEl = document.getElementById('system-clock');
  if (!clockEl) return;

  function update() {
    const now = new Date();
    clockEl.innerText = now.toUTCString().replace('GMT', 'UTC');
  }
  update();
  setInterval(update, 1000);
}

let trendChartInstance = null;
let riskChartInstance = null;

async function loadDashboardData() {
  try {
    const res = await fetch('/api/dashboard/stats');
    if (!res.ok) return;
    const data = await res.json();

    // 1. Update KPI Values
    if (data.kpis) {
      updateKpi('kpi-total-attacks', data.kpis.total_attacks.toLocaleString());
      updateKpi('kpi-unique-ips', data.kpis.unique_ips.toLocaleString());
      updateKpi('kpi-login-attempts', data.kpis.login_attempts.toLocaleString());
      updateKpi('kpi-critical-alerts', data.kpis.critical_alerts.toLocaleString());
    }

    // 2. Render Trend Chart
    const trendCtx = document.getElementById('attackTrendChart');
    if (trendCtx && data.trends) {
      if (trendChartInstance) trendChartInstance.destroy();
      trendChartInstance = CyberCharts.renderTrendChart(trendCtx, data.trends.labels, data.trends.counts);
    }

    // 3. Render Top Usernames
    const userContainer = document.getElementById('top-usernames-container');
    if (userContainer && data.top_usernames) {
      userContainer.innerHTML = data.top_usernames.map(u => `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.03);">
          <span class="mono-cell" style="color: #f8fafc;">${escapeHtml(u.username)}</span>
          <span class="badge badge-medium">${u.count} hits</span>
        </div>
      `).join('');
    }

    // 4. Render Recent Events Table
    const tableBody = document.getElementById('recent-events-tbody');
    if (tableBody && data.recent_events) {
      tableBody.innerHTML = data.recent_events.map(e => `
        <tr>
          <td class="mono-cell">${formatTime(e.timestamp)}</td>
          <td class="mono-cell">${escapeHtml(e.source_ip)}</td>
          <td><span class="badge ${getEventBadgeClass(e.event_type)}">${escapeHtml(e.event_type)}</span></td>
          <td class="mono-cell">${escapeHtml(e.username || '-')}</td>
          <td>${escapeHtml(e.country || 'Unknown')}</td>
        </tr>
      `).join('');
    }

  } catch (err) {
    console.error('Failed to load dashboard statistics:', err);
  }
}

function updateKpi(elementId, value) {
  const el = document.getElementById(elementId);
  if (el) el.innerText = value;
}

function getEventBadgeClass(eventType) {
  if (eventType.includes('success')) return 'badge-critical';
  if (eventType.includes('failed')) return 'badge-high';
  if (eventType.includes('command')) return 'badge-medium';
  return 'badge-low';
}

function formatTime(isoStr) {
  if (!isoStr) return '-';
  const d = new Date(isoStr);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function escapeHtml(text) {
  if (!text) return '';
  return text.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

