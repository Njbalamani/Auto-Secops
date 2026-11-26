LOGGED_PREFIXES = (
    "/api/alerts",
    "/api/incidents",
    "/api/workflows",
    "/api/approvals",
    "/api/reports",
    "/api/intelligence",
    "/api/hunting",
    "/api/saved-hunts",
    "/api/risk-fabric",
    "/api/copilot",
    "/alerts/",
    "/incidents/",
    "/automation/",
    "/reports/",
    "/hunting/",
    "/risk-fabric/",
    "/copilot/",
)


def should_log_path(path):
    return path.startswith(LOGGED_PREFIXES)
