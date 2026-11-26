from django.utils import timezone


class AuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        request.autosecops_started_at = timezone.now()
        return None

    def process_response(self, request, response):
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and getattr(request, "user", None)
            and request.user.is_authenticated
        ):
            from audit.services import log_action
            from config.audit_audit import should_log_path

            if should_log_path(request.path):
                log_action(
                    request.user.organization,
                    request.user,
                    f"{request.method} {request.path}",
                    "HTTPRequest",
                    "",
                    {
                        "status_code": response.status_code,
                        "duration_ms": self._duration_ms(request),
                    },
                    request.META.get("REMOTE_ADDR"),
                )
        return response

    @staticmethod
    def _duration_ms(request):
        started = getattr(request, "autosecops_started_at", None)
        if not started:
            return None
        return int((timezone.now() - started).total_seconds() * 1000)
