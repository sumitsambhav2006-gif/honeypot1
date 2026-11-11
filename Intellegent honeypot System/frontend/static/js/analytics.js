// ==============================================================================
// IHTIP - Analytics & Triage Controller
// ==============================================================================

async function updateAlertStatus(alertId, newStatus) {
  try {
    const res = await fetch(`/api/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });

    if (res.ok) {
      const badge = document.getElementById(`alert-status-${alertId}`);
      if (badge) {
        badge.innerText = newStatus;
        badge.className = `badge ${newStatus === 'resolved' ? 'badge-low' : (newStatus === 'investigating' ? 'badge-medium' : 'badge-high')}`;
      }
    }
  } catch (err) {
    console.error('Error updating alert status:', err);
  }
}

function filterTable(inputId, tableId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const filter = input.value.toLowerCase();
  const table = document.getElementById(tableId);
  if (!table) return;
  const tr = table.getElementsByTagName('tr');

  for (let i = 1; i < tr.length; i++) {
    const text = tr[i].textContent || tr[i].innerText;
    tr[i].style.display = text.toLowerCase().indexOf(filter) > -1 ? '' : 'none';
  }
}

