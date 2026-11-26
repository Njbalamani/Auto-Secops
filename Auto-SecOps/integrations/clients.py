import requests
from django.conf import settings
from django.utils import timezone

from alerts.normalization import ingest_payload
from intelligence.enrichment import import_stix_bundle
from intelligence.models import ThreatIntelligenceRecord


def fetch_wazuh_alerts(organization, source, actor=None):
    if not settings.WAZUH_URL or not settings.WAZUH_USER or not settings.WAZUH_PASSWORD:
        return {"status": "NOT_CONFIGURED", "created": 0, "duplicates": 0, "errors": []}
    try:
        response = requests.get(
            f"{settings.WAZUH_URL.rstrip('/')}/alerts",
            auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD),
            verify=settings.WAZUH_VERIFY_SSL,
            timeout=settings.WAZUH_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        document = response.json()
        payloads = document.get("data", document.get("alerts", []))
        if isinstance(payloads, dict):
            payloads = payloads.get("alerts", [])
    except Exception as exc:
        return {"status": "ERROR", "created": 0, "duplicates": 0, "errors": [str(exc)]}
    created = 0
    duplicates = 0
    errors = []
    for payload in payloads[: settings.UPLOAD_MAX_ROWS]:
        try:
            _, was_created = ingest_payload(payload, organization, source, actor)
            if was_created:
                created += 1
            else:
                duplicates += 1
        except Exception as exc:
            errors.append(str(exc))
    source.last_seen_at = timezone.now()
    source.save(update_fields=["last_seen_at"])
    return {"status": "OK", "created": created, "duplicates": duplicates, "errors": errors}


def fetch_opencti_indicators(organization, actor=None):
    if not settings.OPENCTI_URL or not settings.OPENCTI_TOKEN:
        return {"status": "NOT_CONFIGURED", "created": 0}
    query = {
        "query": """
        query Indicators($count: Int!) {
          indicators(first: $count) {
            edges {
              node {
                id pattern confidence description labels { value }
                externalReferences { source_name external_id }
              }
            }
          }
        }
        """,
        "variables": {"count": 500},
    }
    try:
        response = requests.post(
            f"{settings.OPENCTI_URL.rstrip('/')}/graphql",
            json=query,
            headers={"Authorization": f"Bearer {settings.OPENCTI_TOKEN}"},
            timeout=settings.OPENCTI_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        edges = response.json()["data"]["indicators"]["edges"]
    except Exception as exc:
        return {"status": "ERROR", "created": 0, "detail": str(exc)}
    objects = []
    for edge in edges:
        node = edge.get("node", {})
        objects.append(
            {
                "type": "indicator",
                "pattern": node.get("pattern", ""),
                "confidence": node.get("confidence", 50),
                "description": node.get("description", ""),
                "labels": [
                    label.get("value") for label in node.get("labels", []) if label.get("value")
                ],
                "created_by_ref": node.get("id", "OpenCTI"),
                "external_references": node.get("externalReferences", []),
                "revoked": False,
            }
        )
    created = import_stix_bundle(
        organization,
        {"objects": objects},
        actor,
        source_type=ThreatIntelligenceRecord.SourceType.OPENCTI,
    )
    return {"status": "OK", "created": created}
