# Architecture

AutoSecOps is a modular Django monolith with clear service boundaries.

## Data flow

```text
Sources -> Ingestion -> Normalization -> Deduplication -> Classification
        -> Threat Enrichment -> Detection Evaluation -> Asset Risk Correlation
        -> Incident Creation -> Workflow Evaluation -> Approval Gate
        -> Report Generation -> Dashboard/Audit
```

## Modules

- **accounts**: Custom user model with platform roles: administrator, SOC analyst, incident responder, viewer.
- **organizations**: Tenant boundary for all operational records.
- **alerts**: Alert sources, normalized security alerts, classifications, ingestion services.
- **intelligence**: Indicators, threat intelligence records, STIX/TAXII import, MITRE mapping.
- **incidents**: Security incidents, assignments, investigation notes, timelines, state transitions.
- **detections**: Rule definitions, single-alert and correlation evaluation, deduplicated hits, review and escalation.
- **assets**: Asset inventory, vulnerabilities, deterministic risk scoring, exposure correlation, asset incident creation.
- **automation**: Workflow definitions, executions, approval requests, guarded action engine.
- **reports**: PDF generation using incident evidence, enrichment, timeline, and aggregate metrics.
- **audit**: Central audit log written by services and HTTP mutation middleware.
- **dashboard**: Database-backed KPIs and charts.
- **search**: Tenant-scoped unified search service and result API across all operational modules.
- **hunting**: Structured query parser, read-only correlation across operational records, and saved hunt library.
- **riskfabric**: Live attack-path scoring, exposure summary, and deterministic risk forecast.
- **copilot**: Evidence-backed briefing generator and grounded question routing without external model calls.
- **detections.backtesting**: Historical rule simulation that never creates hits, alerts, incidents, or audit noise.
- **config.system**: Runtime status aggregation for database, storage, static files, task broker, model, integrations, and inventory counts.
- **integrations**: Wazuh API polling, OpenCTI GraphQL import, TAXII collection polling, configuration status.
- **mlengine**: Hybrid classifier with SHAP-backed explainability.

## Classification design

The classifier combines:

1. Deterministic keyword/rule scoring.
2. TF-IDF n-grams with logistic regression.
3. Numeric alert features.
4. SHAP linear explanations where the package is available.

Every classification is persisted with category, risk score, confidence, method, model version, explanation, and evidence. AI output never bypasses analyst review.

## Detection design

Detection rules are deterministic, tenant-scoped definitions with typed conditions. `SINGLE` rules match individual normalized alerts, `CORRELATION` rules group alerts by source IP, user identity, or alert type inside a sliding window, and `THREAT_INTEL` rules match high-confidence malicious intelligence records. Hits are deduplicated with a rule-specific fingerprint. Analysts review hits and explicitly choose whether to create an alert or escalate to an incident.

## Asset risk design

Asset risk is scored from weighted, explainable factors: business criticality, internet exposure, production environment, open CVSS scores, exploitable vulnerabilities, malicious threat-intelligence matches, related alerts, and related detection hits. Every assessment stores its factors and contributing records so analysts can audit why a score changed. Creating an incident from an asset risk assessment is explicit and never performs remediation.

## Authorization

- UI uses Django session authentication and `login_required`.
- API uses session plus JWT authentication.
- Organization-scoped viewsets filter records by the authenticated user's organization.
- Platform administrators may choose an organization via `organization` query/body parameter.
- Sensitive workflows require `Incident Responder` or `Administrator` role.

## Safety boundaries

Sensitive actions are declared in `automation.engine.SENSITIVE_ACTIONS`. They always create approval requests. The bundled engine does not execute external changes. Integration clients only read from external systems; they never write back.

## Persistence

SQLite is used by default for simple local deployment. Set `DATABASE_ENGINE` to a PostgreSQL backend and provide `DB_*` variables for production-style deployments.

## Production topology

`docker-compose.prod.yml` runs PostgreSQL, Redis, a Gunicorn web process, a Celery worker, a Celery beat scheduler, and an nginx reverse proxy. `config/settings_prod.py` enforces a production secret key and allowed hosts, enables secure cookies and HSTS, and uses manifest static assets. WhiteNoise serves compressed static files through Django; nginx also exposes dedicated static and media locations.
