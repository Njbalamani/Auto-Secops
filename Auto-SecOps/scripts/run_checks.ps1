$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Python environment not found at $python"
}

& $python -m ruff check $projectRoot
& $python -m ruff format --check $projectRoot
& $python (Join-Path $projectRoot "manage.py") check
& $python (Join-Path $projectRoot "manage.py") makemigrations --check --dry-run --noinput
& $python (Join-Path $projectRoot "manage.py") test --noinput
