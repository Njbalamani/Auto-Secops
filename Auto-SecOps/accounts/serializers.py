from django.contrib.auth import get_user_model
from rest_framework import serializers

from organizations.models import Organization

User = get_user_model()


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "display_name",
            "organization",
            "organization_name",
            "platform_role",
            "is_active",
            "is_staff",
            "is_superuser",
            "date_joined",
        ]
        read_only_fields = ["date_joined"]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    class Meta:
        model = User
        fields = ["username", "email", "password", "display_name", "organization", "platform_role"]

    def validate_platform_role(self, value):
        allowed = {User.PlatformRole.SOC_ANALYST, User.PlatformRole.VIEWER}
        if value not in allowed:
            raise serializers.ValidationError(
                "Self-registration cannot grant administrative roles."
            )
        return value or User.PlatformRole.VIEWER

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user
