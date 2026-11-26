from rest_framework.response import Response
from rest_framework.views import APIView

from config.permissions import CanManageSOC
from config.system import system_status


class SystemStatusAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        return Response(system_status())
