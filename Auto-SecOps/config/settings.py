import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default):
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def env_list(name, default):
    value = os.getenv(name)
    if not value:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-only-autosecops-secret-change-before-production")
DEBUG = env_bool("DEBUG", True)
ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", ["localhost", "127.0.0.1", "[::1]"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",
    "whitenoise",
    "accounts.apps.AccountsConfig",
    "organizations.apps.OrganizationsConfig",
    "alerts.apps.AlertsConfig",
    "intelligence.apps.IntelligenceConfig",
    "incidents.apps.IncidentsConfig",
    "automation.apps.AutomationConfig",
    "reports.apps.ReportsConfig",
    "audit.apps.AuditConfig",
    "dashboard.apps.DashboardConfig",
    "integrations.apps.IntegrationsConfig",
    "mlengine.apps.MlEngineConfig",
    "detections.apps.DetectionsConfig",
    "assets.apps.AssetsConfig",
    "search.apps.SearchConfig",
    "hunting.apps.HuntingConfig",
    "riskfabric.apps.RiskFabricConfig",
    "copilot.apps.CopilotConfig",
    "config.apps.ConfigConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "config.audit_middleware.AuditMiddleware",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "dashboard.context_processors.platform_context",
            ]
        },
    }
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASE_ENGINE = os.getenv("DATABASE_ENGINE", "django.db.backends.sqlite3")
if DATABASE_ENGINE == "django.db.backends.sqlite3":
    DATABASES = {
        "default": {
            "ENGINE": DATABASE_ENGINE,
            "NAME": BASE_DIR / os.getenv("DB_NAME", "db.sqlite3"),
            "OPTIONS": {"timeout": 20},
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": DATABASE_ENGINE,
            "NAME": os.getenv("DB_NAME", "autosecops"),
            "USER": os.getenv("DB_USER", "autosecops"),
            "PASSWORD": os.getenv("DB_PASSWORD", ""),
            "HOST": os.getenv("DB_HOST", "localhost"),
            "PORT": os.getenv("DB_PORT", "5432"),
        }
    }

AUTH_USER_MODEL = "accounts.User"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {"anon": "20/min", "user": "300/min"},
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": False,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", [])
CORS_ALLOW_CREDENTIALS = True

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
CELERY_TASK_ALWAYS_EAGER = env_bool("CELERY_TASK_ALWAYS_EAGER", False)
CELERY_TASK_EAGER_PROPAGATES = True

SYNTHETIC_DATA_ONLY = env_bool("SYNTHETIC_DATA_ONLY", True)
AUTOSEOPS_PASSWORD = os.getenv("AUTOSEOPS_PASSWORD", "SyntheticPass!123")
AUTOSEOPS_VERSION = os.getenv("AUTOSEOPS_VERSION", "1.0.0")
AUTOSEOPS_DEPLOYMENT = os.getenv("AUTOSEOPS_DEPLOYMENT", "LOCAL_DEMO")
ENABLE_SHAP_EXPLAINER = env_bool("ENABLE_SHAP_EXPLAINER", True)
ALERT_DEDUPLICATION_WINDOW_MINUTES = env_int("ALERT_DEDUPLICATION_WINDOW_MINUTES", 30)
WORKFLOW_TASK_TIMEOUT_SECONDS = env_int("WORKFLOW_TASK_TIMEOUT_SECONDS", 30)
UPLOAD_MAX_MB = env_int("UPLOAD_MAX_MB", 10)
UPLOAD_MAX_ROWS = env_int("UPLOAD_MAX_ROWS", 5000)

WAZUH_ENABLED = env_bool("WAZUH_ENABLED", False)
WAZUH_URL = os.getenv("WAZUH_URL", "")
WAZUH_USER = os.getenv("WAZUH_USER", "")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
WAZUH_VERIFY_SSL = env_bool("WAZUH_VERIFY_SSL", True)
WAZUH_TIMEOUT_SECONDS = env_int("WAZUH_TIMEOUT_SECONDS", 10)

OPENCTI_ENABLED = env_bool("OPENCTI_ENABLED", False)
OPENCTI_URL = os.getenv("OPENCTI_URL", "")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
OPENCTI_TIMEOUT_SECONDS = env_int("OPENCTI_TIMEOUT_SECONDS", 10)

TAXII_ENABLED = env_bool("TAXII_ENABLED", False)
TAXII_URL = os.getenv("TAXII_URL", "")
TAXII_COLLECTION = os.getenv("TAXII_COLLECTION", "")
TAXII_TIMEOUT_SECONDS = env_int("TAXII_TIMEOUT_SECONDS", 10)

AI_MODEL_DISCLAIMER = (
    "AI-assisted classifications are decision support and require analyst validation."
)
