# API Guide

Base URL: `/api/`

## Authentication

Session authentication works for browser use. JWT is available for programmatic clients.

```bash
curl -X POST /api/auth/token/ -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"SyntheticPass!123"}'
```

Send the returned `access` token as `Authorization: Bearer <token>`.

## Alert ingestion

JSON payload:

```bash
curl -X POST /api/alerts/ingest/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "source_name": "Demo API",
    "auto_process": true,
    "payload": {
      "external_id": "API-001",
      "title": "Suspicious login",
      "severity": "HIGH",
      "source_ip": "203.0.113.10",
      "user": "alice",
      "description": "failed password brute force attempts"
    }
  }'
```

File upload:

```bash
curl -X POST /api/alerts/ingest/ \
  -H "Authorization: Bearer <token>" \
  -F "file=@samples/synthetic_alerts.json;type=application/json"
```

CSV upload:

```bash
curl -X POST /api/alerts/ingest/ \
  -H "Authorization: Bearer <token>" \
  -F "file=@samples/synthetic_alerts.csv;type=text/csv"
```

## Threat intelligence

- `POST /api/threat-intelligence/import-stix/` accepts `bundle` JSON or a `file`.
- `POST /api/threat-intelligence/taxii/` polls the configured TAXII collection.

## Incidents and workflows

- `POST /api/incidents/from-alert/` creates an incident from an alert.
- `POST /api/incidents/{id}/assign/` assigns an analyst.
- `POST /api/incidents/{id}/change-status/` changes status.
- `POST /api/incidents/{id}/run-workflows/` evaluates workflows.
- `POST /api/approvals/{id}/decide/` accepts `{"approved": true, "note": "..."}`.

## Detection engineering

- `GET /api/detection-rules/` lists rules; filter with `rule_type` and `enabled`.
- `POST /api/detection-rules/{id}/evaluate/` runs one rule over a `lookback_hours` window.
- `POST /api/detection-rules/evaluate-all/` evaluates all enabled rules; platform admins may pass `organization`.
- `POST /api/detection-rules/{id}/toggle/` enables or disables a rule.
- `GET /api/detection-hits/` lists hits; filter with `status`, `severity`, and `rule`.
- `POST /api/detection-hits/{id}/review/` accepts `{"status":"REVIEWED","note":"..."}`.
- `POST /api/detection-hits/{id}/to-alert/` creates a linked security alert.
- `POST /api/detection-hits/{id}/escalate/` creates or reuses an incident and optionally runs workflows with `run_workflows=true`.
- `GET /api/detection-rules/export-csv/` and `GET /api/detection-hits/export-csv/` return CSV downloads.

Rules are deterministic and organization-scoped. Detection hits are deduplicated by rule and evidence fingerprint; repeated evaluations do not create duplicate findings for the same evidence.

## Asset risk

- `GET /api/assets/` lists assets with `latest_risk_score`, `latest_risk_level`, and `open_vulnerabilities`; filter with `asset_type`, `criticality`, `environment`, `status`, and `internet_exposed`.
- `POST /api/assets/{id}/assess/` stores a new risk assessment for one asset.
- `POST /api/assets/reassess-all/` reassesses all active assets in the requested organization.
- `POST /api/assets/{id}/create-incident/` creates an incident from the latest assessment.
- `GET /api/vulnerabilities/` lists vulnerabilities; filter with `status`, `severity`, and `asset`.
- `POST /api/vulnerabilities/{id}/set-status/` accepts `{"status":"REMEDIATED"}`.
- `GET /api/risk-assessments/latest/` returns the newest assessment for each asset.
- `GET /api/assets/export-csv/` and `GET /api/vulnerabilities/export-csv/` return CSV downloads.

Risk scoring is deterministic and explainable: each assessment stores weighted factors and the alert, detection, and intelligence records that contributed to the score. Asset incident creation is analyst-controlled and never applies infrastructure changes.

## Reports

```bash
curl -X POST /api/reports/generate/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"report_type":"EXECUTIVE"}'
```

Incident reports require `report_type=INCIDENT` and `incident=<id>`.

## Model information and exports

- `GET /api/ml/model-info/` returns classifier version, training corpus counts, vocabulary size, and SHAP status.
- `GET /api/alerts/export-csv/`, `GET /api/incidents/export-csv/`, and `GET /api/audit-logs/export-csv/` return CSV downloads using the same organization scoping and filters as their list endpoints.

## Asynchronous processing

`POST /api/alerts/{id}/process-async/` queues `alerts.tasks.process_alert_task` when Redis/Celery is available. If the broker is unavailable, the API returns `503 BROKER_UNAVAILABLE` with a hint to use synchronous endpoints. No functionality depends on Celery for local demonstration use.

## Search and system status

- `GET /api/search/?q=203.0.113.10&limit=8` returns grouped matches from alerts, incidents, detections, assets, vulnerabilities, indicators, audit logs, and reports.
- `GET /api/system/status/` returns version, deployment mode, uptime, database/storage/static/task-broker checks, live inventory counts, classifier metadata, and integration status.
- `GET /health/live/` includes service version and deployment mode.

## Advanced operations

- `POST /api/hunting/execute/` accepts `{"query": "severity:HIGH type:alert ip:203.0.113"}` and returns read-only grouped hunt results with parsed filters and summary counts.
- `GET/POST/PUT/DELETE /api/saved-hunts/` manages reusable hunts; `POST /api/saved-hunts/{id}/run/` executes and records a saved hunt.
- `GET /api/risk-fabric/summary/` returns live exposure counts and the highest-priority path.
- `GET /api/risk-fabric/attack-paths/?limit=10` returns scored paths with steps, evidence, impact, likelihood, and recommendations.
- `GET /api/risk-fabric/forecast/?days=7` returns deterministic risk direction, confidence, and drivers.
- `GET /api/copilot/briefing/` returns an evidence-backed shift briefing with priority actions and a watchlist.
- `POST /api/copilot/ask/` accepts `{"question": "What should we prioritize?"}` and routes to incident, detection, exposure, recommendation, or briefing intents.
- `POST /api/detection-rules/{id}/backtest/` and `POST /api/detection-rules/backtest-all/` simulate detection coverage without creating hits, alerts, or incidents.

Advanced endpoints remain tenant-scoped, use `CanManageSOC`, and are decision-support only. No endpoint performs an infrastructure action.

## Health

- `GET /health/live/`
- `GET /health/ready/`
- `GET /health/integrations/`
