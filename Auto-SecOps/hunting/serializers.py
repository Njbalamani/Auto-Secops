from rest_framework import serializers

from hunting.models import SavedHunt


class SavedHuntSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavedHunt
        fields = "__all__"
        read_only_fields = [
            "id",
            "created_by",
            "last_run_at",
            "last_result_count",
            "created_at",
            "updated_at",
        ]
