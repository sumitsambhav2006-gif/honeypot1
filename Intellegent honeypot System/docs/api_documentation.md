# REST API Specification & Endpoint Documentation

## 1. Authentication
Endpoints under administrative governance require active session authentication or standard API headers.
- **Login:** `POST /api/auth/login`
- **Logout:** `POST /api/auth/logout`
- **User Session:** `GET /api/auth/me`

## 2. Executive Dashboard Endpoints
### `GET /api/dashboard/stats`
Returns aggregated KPI counts, 7-day attack timeseries, top attacked usernames, and recent events.
```json
{
  "kpis": {
    "total_attacks": 1284,
    "unique_ips": 347,
    "login_attempts": 892,
    "critical_alerts": 26,
    "active_sessions": 3
  },
  "trends": {
    "labels": ["2026-11-02", "2026-11-03", "..."],
    "counts": [140, 192, 215]
  }
}
```

### `GET /api/dashboard/live-stream`
Server-Sent Events (SSE) stream emitting real-time JSON events as they are captured by Cowrie.

## 3. Threat Intelligence & Attackers
### `GET /api/attackers`
Query Parameters:
- `limit` (int, default: 50)
- `country` (string)
- `min_reputation` (int)

### `GET /api/attackers/{id}`
Returns complete attacker profile including geolocation, ASN, historical sessions, and recent events.

## 4. Sessions & Forensics
### `GET /api/sessions`
Returns recorded interactive shell sessions with duration and risk score.

### `GET /api/sessions/{session_id}/commands`
Returns chronological command timeline executed within the session, categorized with risk points.

## 5. Alerts & Triage
### `GET /api/alerts`
Returns active security alerts. Filterable by `severity` and `status`.

### `PATCH /api/alerts/{id}`
Updates alert triage state:
```json
{ "status": "investigating" } // or "resolved", "dismissed"
```

## 6. Reports & Export
### `GET /api/reports/export`
Query Parameters:
- `format`: `csv` or `pdf`
- `type`: `attacks`, `attackers`, `commands`, `alerts`

