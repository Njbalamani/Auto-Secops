from django.conf import settings

from alerts.models import AlertSource
from audit.services import log_action
from integrations.clients import fetch_opencti_indicators, fetch_wazuh_alerts


def integration_status():
    return {
        "mode": "LOCAL_DEMO"
        if not any([settings.WAZUH_ENABLED, settings.OPENCTI_ENABLED, settings.TAXII_ENABLED])
        else "CONFIGURED",
        "synthetic_data_only": settings.SYNTHETIC_DATA_ONLY,
        "integrations": [
            {
                "name": "Wazuh",
                "enabled": settings.WAZUH_ENABLED,
                "configured": bool(
                    settings.WAZUH_URL and settings.WAZUH_USER and settings.WAZUH_PASSWORD
                ),
                "status": "ENABLED"
                if settings.WAZUH_ENABLED and settings.WAZUH_URL
                else "NOT_CONFIGURED",
                "detail": "REST API polling"
                if settings.WAZUH_URL
                else "Set WAZUH_URL to enable polling.",
            },
            {
                "name": "OpenCTI",
                "enabled": settings.OPENCTI_ENABLED,
                "configured": bool(settings.OPENCTI_URL and settings.OPENCTI_TOKEN),
                "status": "ENABLED"
                if settings.OPENCTI_ENABLED and settings.OPENCTI_URL
                else "NOT_CONFIGURED",
                "detail": "STIX indicator import"
                if settings.OPENCTI_URL
                else "Set OPENCTI_URL to enable import.",
            },
            {
                "name": "TAXII",
                "enabled": settings.TAXII_ENABLED,
                "configured": bool(settings.TAXII_URL and settings.TAXII_COLLECTION),
                "status": "ENABLED"
                if settings.TAXII_ENABLED and settings.TAXII_URL
                else "NOT_CONFIGURED",
                "detail": "TAXII collection polling"
                if settings.TAXII_URL
                else "Set TAXII_URL to enable polling.",
            },
        ],
    }


def get_or_create_source(organization, name, kind, identifier=""):
    source, _ = AlertSource.objects.get_or_create(
        organization=organization,
        name=name,
        kind=kind,
        defaults={"identifier": identifier, "enabled": True},
    )
    return source


def sync_wazuh(organization, actor=None):
    if not settings.WAZUH_ENABLED:
        return {"status": "NOT_CONFIGURED", "created": 0, "duplicates": 0, "errors": []}
    source = get_or_create_source(
        organization, "Wazuh Integration", AlertSource.Kind.WAZUH, settings.WAZUH_URL
    )
    result = fetch_wazuh_alerts(organization, source, actor)
    log_action(organization, actor, "integration.wazuh_sync", "AlertSource", source.id, result)
    return result


def sync_opencti(organization, actor=None):
    if not settings.OPENCTI_ENABLED:
        return {"status": "NOT_CONFIGURED", "created": 0}
    result = fetch_opencti_indicators(organization, actor)
    log_action(organization, actor, "integration.opencti_sync", "", "", result)
    return result
