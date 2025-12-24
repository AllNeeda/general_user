from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.views import TokenObtainPairView
import random


class RoleViewPermission(BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        # Allow both "super-admin" and "freelance-service-admin" roles
        allowed_roles = ["super-admin", "freelance-service-admin"]
        return hasattr(request.user, 'role') and request.user.role.name in allowed_roles

    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
        # Allow both "super-admin" and "freelance-service-admin" roles
        allowed_roles = ["super-admin", "freelance-service-admin"]
        return hasattr(request.user, 'role') and request.user.role.name in allowed_roles



class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        # role is now a ForeignKey, so use role.name
        role_name = user.role.name if hasattr(user, 'role') and user.role else None
        token['role'] = [role_name] if role_name else []
        token['sub'] = str(user.id)    # rename user_id -> sub
        # Optionally remove default 'user_id'
        if 'user_id' in token:
            del token['user_id']
        return token



def generate_otp():
    return f"{random.randint(1000, 9999)}"

