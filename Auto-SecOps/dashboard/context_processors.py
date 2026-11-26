from django.conf import settings


def platform_context(request):
    return {
        "platform_name": "AutoSecOps",
        "synthetic_data_only": settings.SYNTHETIC_DATA_ONLY,
        "ai_disclaimer": settings.AI_MODEL_DISCLAIMER,
        "platform_version": settings.AUTOSEOPS_VERSION,
        "deployment_mode": settings.AUTOSEOPS_DEPLOYMENT,
    }
