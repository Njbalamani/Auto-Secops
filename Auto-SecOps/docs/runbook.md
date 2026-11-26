# Operations Runbook

## Daily checks

- Open the dashboard and confirm metrics are generated from database records.
- Review `/automation/` for pending approval requests.
- Review `/audit/` for unexpected mutations.
- Confirm `/health/ready/` returns `ready`.
- Confirm `/health/integrations/` shows expected configuration status.
- Open `/system/` and confirm database, storage, static assets, and task broker state are understood.
- Use `/search/` to pivot quickly between alerts, incidents, detections, assets, indicators, and audit events.
- Check `/api/ml/model-info/` to confirm the expected classifier version and corpus size.
- Review `/detections/` for new detection hits and enabled rules.
- Review `/assets/` for critical risk assets and exploitable vulnerabilities.
- Open `/risk-fabric/` and confirm the highest scoring attack path is understood.
- Open `/copilot/` and review the shift briefing before triage.
- Use `/hunting/` for structured pivots and save high-value queries to the hunt library.
- Backtest new or changed detection rules with `/detections/` before enabling them broadly.
- Export CSV evidence from `/api/alerts/export-csv/`, `/api/incidents/export-csv/`, `/api/audit-logs/export-csv/`, `/api/detection-rules/export-csv/`, `/api/detection-hits/export-csv/`, `/api/assets/export-csv/`, or `/api/vulnerabilities/export-csv/` when offline review is needed.

## Alert triage

1. Open `/alerts/`.
2. Ingest a JSON payload or upload a JSON/CSV file.
3. Run Normalize, Classify, and Enrich.
4. Create an incident from a high-risk alert.
5. Open `/incidents/`, assign an analyst, add notes, and update status.

## Detection review

1. Open `/detections/`.
2. Run `.\.venv\Scripts\python.exe manage.py seed_detections` once when upgrading an existing database.
3. Run `Evaluate all enabled rules` after new alerts or threat intelligence are ingested.
3. Review hit evidence, then choose `Create alert`, `Review`, or `Escalate to incident`.
4. Escalation reuses an existing incident for the linked alert when possible.
5. Use rule filters in the API for rule type, enablement, status, severity, and source rule.

## Asset risk review

1. Open `/assets/`.
2. Run `.\.venv\Scripts\python.exe manage.py seed_assets` once when upgrading an existing database.
3. Run `Reassess all active assets` after ingesting new alerts, detection hits, or threat intelligence.
4. Review the score factors in `GET /api/risk-assessments/latest/` for explainability.
5. Create an incident only after analyst confirmation; no blocking or isolation is performed.

## Incident response

- Use status transitions: New -> In Progress -> Resolved -> Closed.
- Use `Run workflows` only after classification and enrichment are complete.
- Sensitive actions require responder/admin approval in `/automation/`.
- Generate an incident PDF from the incident page or API.

## Integrations

External integrations are disabled by default. Configure only the systems you are authorized to read from:

- Wazuh: `WAZUH_ENABLED`, `WAZUH_URL`, `WAZUH_USER`, `WAZUH_PASSWORD`.
- OpenCTI: `OPENCTI_ENABLED`, `OPENCTI_URL`, `OPENCTI_TOKEN`.
- TAXII: `TAXII_ENABLED`, `TAXII_URL`, `TAXII_COLLECTION`.

If configuration is missing, status pages show `NOT_CONFIGURED` and local synthetic mode remains available.

## Failure handling

- Invalid JSON/CSV uploads return validation errors without partial processing of the malformed item.
- TAXII and Wazuh polling failures are caught and returned as status errors; existing data is preserved.
- Classification and enrichment failures are logged to the audit trail where applicable.
- Report generation creates database metadata before writing the PDF; rerun generation if a PDF file is missing.

## Threat hunting and risk review

1. Open `/hunting/` and enter tokens such as `severity:HIGH type:alert ip:203.0.113`.
2. Combine structured tokens with free text to narrow results across alerts, incidents, detections, assets, vulnerabilities, and indicators.
3. Save repeatable hunts with a clear name and description.
4. Open `/risk-fabric/` to review exposure counts, forecast trend, entry points, lateral targets, and recommended remediation.
5. Treat attack paths as decision support; validate evidence before any analyst-approved action.

## Copilot and detection validation

1. Open `/copilot/` for a shift briefing grounded in live records.
2. Ask scoped questions such as `What should we prioritize?`, `Show open incidents`, or `Show exploitable vulnerabilities`.
3. Confirm each recommendation cites a live record and requires human approval for any follow-up.
4. In `/detections/`, use `Backtest` or `Backtest all rules` before promoting rules into routine monitoring.
5. Backtests are read-only simulations and never create production hits, alerts, incidents, or infrastructure changes.

## Deployment operations

- Local development: `docker compose up --build`.
- Production-style stack: `docker compose -f docker-compose.prod.yml up -d --build`.
- Production verification: set `DJANGO_SECRET_KEY`, then run `powershell -File scripts\production_check.ps1`.
- Backups should include the PostgreSQL volume and the media volume, which stores generated PDF reports.
- Celery worker handles asynchronous alert processing, detection evaluation, and asset reassessment; Celery beat runs the hourly maintenance task that evaluates detections and reassesses assets for every organization.

## Safety reminder

Do not extend the automation engine with external blocking, account disablement, isolation, or destructive actions unless the deployment has explicit written authorization, role-gated approval, change logging, and a tested rollback procedure.
