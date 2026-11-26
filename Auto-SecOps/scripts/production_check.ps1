$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Python environment not found at $python"
}
if (-not $env:DJANGO_SECRET_KEY) {
    throw "Set DJANGO_SECRET_KEY before running production checks."
}

$env:DJANGO_SETTINGS_MODULE = "config.settings_prod"
$env:DEBUG = "False"
$env:ALLOWED_HOSTS = if ($env:ALLOWED_HOSTS) { $env:ALLOWED_HOSTS } else { "localhost,127.0.0.1" }
$env:SECURE_SSL_REDIRECT = "False"
$env:SYNTHETIC_DATA_ONLY = if ($env:SYNTHETIC_DATA_ONLY) { $env:SYNTHETIC_DATA_ONLY } else { "False" }

& $python (Join-Path $projectRoot "manage.py") check --deploy --settings=config.settings_prod
& $python (Join-Path $projectRoot "manage.py") makemigrations --check --dry-run --noinput
& $python (Join-Path $projectRoot "manage.py") test --noinput
& $python (Join-Path $projectRoot "manage.py") collectstatic --noinput
