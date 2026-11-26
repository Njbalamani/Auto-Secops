from django.conf import settings
from rest_framework.response import Response
from rest_framework.views import APIView

from config.permissions import CanManageSOC
from mlengine.classifier import model_info


class ModelInfoAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        data = model_info()
        data["external_model_configured"] = bool(settings.OPENCTI_URL or settings.TAXII_URL)
        return Response(data)
