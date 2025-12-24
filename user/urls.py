from django.urls import path
from .views import (
    CreateView,
    GetRoleById,
    RoleView,
    GetllAllRoles,
    GetUserApiView,
    GetUserById,
    DeleteUserById,
    GenerateOTPAPIView,
    VerifyOTPView,
    DeleteRole,
)

urlpatterns = [
    # user routes
    path('user/create/', CreateView.as_view(), name='user-create'),
    path('user/getAll/', GetUserApiView.as_view(), name='user-list'),
    path('user/getById/<uuid:pk>/', GetUserById.as_view(), name='single-user'),
    path('user/delete/<uuid:pk>/', DeleteUserById.as_view(), name='delete-user'),

    # otp routes
    path('authentication/sendOtp/', GenerateOTPAPIView.as_view(), name='send-otp'),
    path('authentication/verify_otp/', VerifyOTPView.as_view(), name='verify-otp'),

    path('role/create/', RoleView.as_view(), name='role-create'),
    path('role/getAll/', GetllAllRoles.as_view(), name='role-list'),
    path('role/getById/<uuid:pk>/', GetRoleById.as_view(), name='single-role'),
    path('role/delete/<uuid:pk>/', DeleteRole.as_view(), name='delete-role'),
]