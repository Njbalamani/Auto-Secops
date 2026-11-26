from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.api import request_organization
from audit.services import log_action
from config.permissions import CanManageSOC
from copilot.services import answer_question, build_briefing


class CopilotBriefingAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        organization = request_organization(request)
        log_action(
            organization,
            request.user,
            "copilot.briefing",
            "AnalystBriefing",
            "",
            {"organization": organization.slug},
        )
        return Response(build_briefing(organization, request.user))


class CopilotAskAPIView(APIView):
    permission_classes = [CanManageSOC]

    def post(self, request):
        organization = request_organization(request)
        question = request.data.get("question", "")
        if not str(question).strip():
            raise ValidationError("question is required.")
        answer = answer_question(organization, question, request.user)
        log_action(
            organization,
            request.user,
            "copilot.ask",
            "AnalystBriefing",
            "",
            {"question": str(question)[:300], "intent": answer["intent"]},
        )
        return Response(answer)
