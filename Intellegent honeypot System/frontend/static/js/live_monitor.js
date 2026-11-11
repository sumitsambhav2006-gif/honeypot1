// ==============================================================================
// IHTIP - Live Attack Stream & Real-Time Cyber Terminal
// ==============================================================================

let eventSource = null;
let eventCounter = 0;

document.addEventListener('DOMContentLoaded', () => {
  initLiveStream();
  initSimulatorControls();
});

function initLiveStream() {
  const terminalBody = document.getElementById('terminal-stream');
  if (!terminalBody) return;

  if (!!window.EventSource) {
    eventSource = new EventSource('/api/dashboard/live-stream');

    eventSource.onmessage = function(e) {
      try {
        const evt = JSON.parse(e.data);
        appendTerminalLine(terminalBody, evt);
      } catch (err) {
        console.error('Error parsing SSE event:', err);
      }
    };

    eventSource.onerror = function() {
      // Reconnection handled automatically by browser EventSource
      console.warn('Live event stream disconnected, retrying...');
    };
  } else {
    // Fallback polling if SSE unsupported
    setInterval(pollRecentEvents, 3000);
  }
}

function appendTerminalLine(container, evt) {
  eventCounter++;
  const timeStr = evt.timestamp ? new Date(evt.timestamp + (evt.timestamp.endsWith('Z') ? '' : 'Z')).toLocaleTimeString() : new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = 'terminal-line';

  let eventClass = 'line-event';
  if (evt.event_type.includes('failed')) eventClass += ' failed';
  else if (evt.event_type.includes('success')) eventClass += ' crit';
  else if (evt.event_type.includes('command') || evt.event_type.includes('file_download')) eventClass += ' cmd';

  let extraDetail = '';
  try {
    if (evt.raw_payload) {
      const parsed = typeof evt.raw_payload === 'string' ? JSON.parse(evt.raw_payload) : evt.raw_payload;
      if (parsed.input) {
        extraDetail = `<span style="color:#00e5ff; font-weight:700;">$ ${escapeHtml(parsed.input)}</span>`;
      } else if (parsed.url) {
        extraDetail = `<span style="color:#f59e0b;">URL: ${escapeHtml(parsed.url)}</span>`;
      }
    }
  } catch (err) {}

  line.innerHTML = `
    <span class="line-ts">[${timeStr}]</span>
    <span class="line-ip">${escapeHtml(evt.source_ip)}</span>
    <span class="${eventClass}">${escapeHtml(evt.event_type)}</span>
    ${evt.username ? `<span>user: <b style="color:#f8fafc">${escapeHtml(evt.username)}</b></span>` : ''}
    ${extraDetail}
    ${evt.password_masked ? `<span style="color:#64748b">pwd: ${escapeHtml(evt.password_masked)}</span>` : ''}
    <span style="color:#94a3b8">geo: ${escapeHtml(evt.country || 'Unknown')}</span>
  `;

  container.prepend(line);

  // Keep only the last 150 lines
  while (container.children.length > 150) {
    container.removeChild(container.lastChild);
  }

  // Update live counter badge
  const counterEl = document.getElementById('live-stream-counter');
  if (counterEl) counterEl.innerText = `${eventCounter} Live Ingests`;
}

async function pollRecentEvents() {
  const container = document.getElementById('terminal-stream');
  if (!container) return;
  try {
    const res = await fetch('/api/dashboard/stats');
    const data = await res.json();
    if (data.recent_events && data.recent_events.length > 0) {
      appendTerminalLine(container, data.recent_events[0]);
    }
  } catch (e) {}
}

function initSimulatorControls() {
  const simBtn = document.getElementById('trigger-sim-btn');
  if (!simBtn) return;

  simBtn.addEventListener('click', async () => {
    simBtn.disabled = true;
    simBtn.innerText = 'Launching Real Attack...';
    try {
      await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'auto' })
      });
      setTimeout(() => {
        simBtn.disabled = false;
        simBtn.innerText = '⚡ Launch Live Attack';
      }, 2500);
    } catch (e) {
      simBtn.disabled = false;
      simBtn.innerText = '⚡ Launch Live Attack';
    }
  });
}

function copyCommand(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerText;
    btn.innerText = 'Copied!';
    setTimeout(() => { btn.innerText = orig; }, 1200);
  });
}

