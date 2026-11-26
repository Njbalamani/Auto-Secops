from datetime import timedelta

from django.utils import timezone

from assets.definitions import SYNTHETIC_ASSETS, SYNTHETIC_VULNERABILITIES
from assets.models import Asset, Vulnerability
from assets.services import reassess_assets


def seed_asset_data(organization, actor=None):
    for definition in SYNTHETIC_ASSETS:
        defaults = dict(definition)
        defaults["last_seen_at"] = timezone.now()
        Asset.objects.get_or_create(
            organization=organization,
            asset_id=definition["asset_id"],
            defaults=defaults,
        )
    assets_by_id = {
        asset.asset_id: asset for asset in Asset.objects.filter(organization=organization)
    }
    for definition in SYNTHETIC_VULNERABILITIES:
        defaults = dict(definition)
        asset = assets_by_id[defaults.pop("asset_id")]
        due_days = int(defaults.pop("due_days"))
        defaults["due_at"] = timezone.now() + timedelta(days=due_days)
        defaults["evidence"] = {"source": "synthetic seed"}
        Vulnerability.objects.get_or_create(
            organization=organization,
            asset=asset,
            cve=defaults["cve"],
            defaults=defaults,
        )
    results = reassess_assets(organization, actor)
    return {
        "assets": len(SYNTHETIC_ASSETS),
        "vulnerabilities": len(SYNTHETIC_VULNERABILITIES),
        "results": results,
    }
