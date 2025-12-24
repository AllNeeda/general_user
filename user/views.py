from django.shortcuts import get_object_or_404
from rest_framework import generics
from django.contrib.auth import get_user_model
from rest_framework.permissions import AllowAny
from django.db import IntegrityError
from django.db.models import Q
from datetime import timedelta

from .serializers import CreateSerializer, OTPSerializer, RoleSerializer, UserListSerializer, VerifySerializer
from .models import OTP, Role, User
from .utils import RoleViewPermission, generate_otp, CustomTokenObtainPairSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
import hashlib
import string


class RoleView(APIView):
    permission_classes = [IsAuthenticated, RoleViewPermission]

    def post(self, request, *args, **kwargs):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetllAllRoles(APIView):
    def get(self, request):
        try:
            queryset = Role.objects.all().order_by('-id')
            page = int(request.query_params.get('page', 1))
            items_per_page = int(request.query_params.get('limit', 10))
            total_items = queryset.count()
            total_pages = (total_items + items_per_page - 1) // items_per_page

            offset = (page - 1) * items_per_page
            paged_queryset = queryset[offset:offset + items_per_page]

            data = []
            for role in paged_queryset:
                data.append({
                    "_id": str(getattr(role, "id", "")),
                    "name": getattr(role, "name", ""),
                    "status": getattr(role, "status", True),
                    "created_by": getattr(role, "created_by_id", None),
                    "updated_by": getattr(role, "updated_by_id", None),
                    "created_at": getattr(role, "created_at", None).isoformat() if getattr(role, "created_at", None) else None,
                    "updated_at": getattr(role, "updated_at", None).isoformat() if getattr(role, "updated_at", None) else None,
                    "role_id": getattr(role, "id", None)
                })

            pagination = {
                "currentPage": page,
                "totalPages": total_pages,
                "totalItems": total_items,
                "itemsPerPage": items_per_page,
                "hasNextPage": page < total_pages,
                "hasPrevPage": page > 1
            }

            response = {
                "success": True,
                "message": "Roles retrieved successfully",
                "data": data,
                "pagination": pagination,
                "timestamp": timezone.now().isoformat()
            }

            return Response(response, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "message": "An error occurred while retrieving roles",
                "error": str(e),
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class GetRoleById(APIView):
    def get(self, request, pk):
        roles = get_object_or_404(Role,pk=pk)
        serializer = RoleSerializer(roles)
        return Response(serializer.data)


class DeleteRole(APIView):
    permission_classes = [IsAuthenticated, RoleViewPermission]
    
    def delete(self, request, pk):
        from django.db import transaction

        try:
            try:
                role = Role.objects.get(pk=pk)
            except Role.DoesNotExist:
                return Response({
                    "success": False,
                    "message": "Role not found",
                    "data": None,
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_404_NOT_FOUND)

            try:
                with transaction.atomic():
                    users_with_role = User.objects.filter(role=role)
                    users_with_role_count = users_with_role.count()
                    users_with_role.delete()

                    role.delete()
            except Exception as delete_ex:
                return Response({
                    "success": False,
                    "message": "An error occurred while deleting the role",
                    "error": str(delete_ex),
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({
                "success": True,
                "message": "Role and all related users deleted successfully",
                "data": None,
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "message": "An error occurred while deleting the role",
                "error": str(e),
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CreateView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = CreateSerializer
    
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            
            # Return custom response format
            return Response({
                "success": True,
                "message": "User created successfully",
                "data": serializer.data,
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED, headers=headers)
        except IntegrityError as e:
            # Handle database integrity errors
            error_message = str(e)
            if "username" in error_message.lower():
                return Response({
                    "success": False,
                    "message": "User creation failed due to username conflict. Please try again.",
                    "error": "A user with this phone number may already exist.",
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
            elif "phoneNo" in error_message.lower() or "phone" in error_message.lower():
                return Response({
                    "success": False,
                    "message": "User creation failed. Phone number already exists.",
                    "error": "A user with this phone number already exists.",
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    "success": False,
                    "message": "User creation failed due to database constraint violation.",
                    "error": str(e),
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Handle any other unexpected errors
            return Response({
                "success": False,
                "message": "An error occurred while creating the user.",
                "error": str(e),
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetUserApiView(APIView):
    
    def get(self, request):
        try:
            # Get query parameters
            page = int(request.query_params.get('page', 1))
            limit = int(request.query_params.get('limit', 10))
            search = request.query_params.get('search', '').strip()
            status_filter = request.query_params.get('status', '').strip()
            role_id = request.query_params.get('role_id', '').strip()
            sort_by = request.query_params.get('sortBy', 'created_at').strip()
            sort_order = request.query_params.get('sortOrder', 'desc').strip().lower()
            
            # Validate pagination parameters
            if page < 1:
                page = 1
            if limit < 1:
                limit = 10
            if limit > 100:  # Max limit to prevent performance issues
                limit = 100
            
            # Start with base queryset
            queryset = User.objects.all()
            
            # Apply search filter
            if search:
                queryset = queryset.filter(
                    Q(firstName__icontains=search) |
                    Q(lastName__icontains=search) |
                    Q(phoneNo__icontains=search)
                )
            
            # Apply status filter
            if status_filter.lower() == 'true':
                queryset = queryset.filter(status=True)
            elif status_filter.lower() == 'false':
                queryset = queryset.filter(status=False)
            
            # Apply role filter
            if role_id:
                try:
                    queryset = queryset.filter(role_id=role_id)
                except (ValueError, TypeError):
                    # Invalid UUID format, return empty results
                    queryset = queryset.none()
            
            # Apply sorting
            # Validate sort_by field to prevent SQL injection
            # Map 'created_at' to 'date_joined' since User model uses date_joined from AbstractUser
            sort_field_mapping = {
                'created_at': 'date_joined',
                'firstName': 'firstName',
                'lastName': 'lastName',
                'phoneNo': 'phoneNo',
                'dob': 'dob',
                'status': 'status',
                'date_joined': 'date_joined'
            }
            
            # Use mapped field or default to date_joined
            sort_by = sort_field_mapping.get(sort_by, 'date_joined')
            
            # Determine sort order
            if sort_order == 'asc':
                sort_prefix = ''
            else:  # default to desc
                sort_prefix = '-'
            
            queryset = queryset.order_by(f'{sort_prefix}{sort_by}')
            
            # Calculate pagination
            total_count = queryset.count()
            total_pages = (total_count + limit - 1) // limit  # Ceiling division
            
            # Apply pagination
            start = (page - 1) * limit
            end = start + limit
            paginated_queryset = queryset[start:end]
            
            # Serialize data
            serializer = UserListSerializer(paginated_queryset, many=True)
            
            # Return paginated response with updated key names
            return Response({
                "success": True,
                "message": "Users retrieved successfully",
                "data": serializer.data,
                "pagination": {
                    "currentPage": page,
                    "totalPages": total_pages,
                    "totalItems": total_count,
                    "itemsPerPage": limit,
                    "hasNextPage": page < total_pages,
                    "hasPrevPage": page > 1
                },
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except ValueError as e:
            return Response({
                "success": False,
                "message": "Invalid query parameters",
                "error": str(e),
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "success": False,
                "message": "An error occurred while fetching users",
                "error": str(e),
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetUserById(APIView):
    def get(self,request, pk):
        try:
            try:
                user = User.objects.get(pk=pk)
            except User.DoesNotExist:
                return Response({
                    "success": False,
                    "message": "User not found",
                    "data": None,
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_404_NOT_FOUND)

            # Build updated_by details if the relation exists on the model
            updated_by_data = None
            if hasattr(user, "updated_by") and user.updated_by:
                updated_by_user = user.updated_by
                updated_by_data = {
                    "_id": str(updated_by_user.id),
                    "firstName": getattr(updated_by_user, "firstName", None),
                    "lastName": getattr(updated_by_user, "lastName", None),
                    "phoneNo": getattr(updated_by_user, "phoneNo", None),
                    "user_id": getattr(updated_by_user, "id", None),
                    "Email": getattr(updated_by_user, "email", None),
                }

            dob_value = None
            if user.dob:
                dob_value = f"{user.dob.isoformat()}T00:00:00.000Z"

            data = {
                "language_id": None,
                "country_id": None,
                "state_id": None,
                "city_id": None,
                "invitedBy": None,
                "_id": str(user.id),
                "firstName": user.firstName,
                "lastName": user.lastName,
                "phoneNo": user.phoneNo,
                "dob": dob_value,
                "isAgreeTermsConditions": user.isAgreeTermsConditions,
                "role_id": user.role.id if user.role else None,
                "status": user.status,
                "Islogin_permissions": True,
                "Permissions_DeviceLocation": False,
                "hobby": [],
                "created_by": None,
                "updated_by": updated_by_data,
                "created_at": user.date_joined.isoformat() if user.date_joined else timezone.now().isoformat(),
                "updated_at": timezone.now().isoformat(),
                "user_id": getattr(user, "id", None),
                "Email": getattr(user, "email", None),
                "RegistrationType": "Individual",
                "freeTrialPlan": False
            }

            return Response({
                "success": True,
                "message": "User retrieved successfully",
                "data": data,
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "message": "An error occurred while fetching the user",
                "error": str(e),
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteUserById(APIView):
    def delete(self, request, pk):
        try:
            try:
                user = User.objects.get(pk=pk)
            except User.DoesNotExist:
                return Response({
                    "success": False,
                    "message": "User not found",
                    "data": None,
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_404_NOT_FOUND)

            user.delete()

            return Response({
                "success": True,
                "message": "User deleted successfully",
                "data": None,
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "message": "An error occurred while deleting the user",
                "error": str(e),
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GenerateOTPAPIView(APIView):
    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_no = serializer.validated_data['phoneNo']

        OTP.objects.filter(
            phoneNo=phone_no,
            is_verified=False
        ).delete()

        otp = generate_otp()

        otp_obj = OTP.objects.create(
            phoneNo=phone_no,
            otp=otp
        )

        expires_at = (otp_obj.created_at + timedelta(minutes=5)).isoformat()

        return Response({
            "success": True,
            "message": "OTP resent successfully",
            "data": {
                "message": "OTP resent successfully",
                "otp": otp,
                "expiresAt": expires_at,
            },
            "timestamp": timezone.now().isoformat()
        }, status=status.HTTP_201_CREATED)



class VerifyOTPView(APIView):
    def post(self, request):
        try:
            serializer = VerifySerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            phone_no = serializer.validated_data.get("phoneNo")
            otp_value = serializer.validated_data.get("otp")

            if not phone_no or not otp_value:
                return Response({
                    "success": False,
                    "message": "phoneNo and otp are required",
                    "data": None,
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get the latest unverified OTP for this phone number
            otp_obj = OTP.objects.filter(
                phoneNo=phone_no,
                is_verified=False
            ).order_by("-created_at").first()

            if not otp_obj or str(otp_obj.otp) != str(otp_value):
                return Response({
                    "success": False,
                    "message": "Invalid OTP",
                    "data": None,
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)

            if otp_obj.is_expired():
                return Response({
                    "success": False,
                    "message": "OTP has expired",
                    "data": None,
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)

            # Mark OTP as verified
            otp_obj.is_verified = True
            otp_obj.save(update_fields=["is_verified"])

            # Get user by phone number
            try:
                user = User.objects.get(phoneNo=phone_no)
            except User.DoesNotExist:
                return Response({
                    "success": False,
                    "message": "User not found for this phone number",
                    "data": None,
                    "timestamp": timezone.now().isoformat()
                }, status=status.HTTP_404_NOT_FOUND)

            # Generate JWT tokens with custom claims
            # Get refresh token with custom claims using CustomTokenObtainPairSerializer
            refresh_token_obj = CustomTokenObtainPairSerializer.get_token(user)
            
            # Create access token with custom claims
            # We need to create it properly with user_id for authentication to work
            access_token = AccessToken.for_user(user)
            role_name = user.role.name if hasattr(user, 'role') and user.role else None
            access_token['role'] = [role_name] if role_name else []
            access_token['sub'] = str(user.id)
            # Keep user_id for authentication - don't remove it
            
            # Use the refresh token object for the refresh token string
            refresh = refresh_token_obj

            # Format user data similar to CreateSerializer
            def generate_referral_code(user_instance):
                """Generate a consistent referral code based on user ID"""
                alphabet = string.ascii_uppercase + string.digits
                seed = str(user_instance.id).encode()
                hash_obj = hashlib.md5(seed)
                hash_hex = hash_obj.hexdigest()[:10]
                code = ''.join(alphabet[int(hash_hex[i], 16) % len(alphabet)] for i in range(10))
                return code

            user_data = {
                "language_id": None,
                "country_id": None,
                "state_id": None,
                "city_id": None,
                "_id": str(user.id),
                "firstName": user.firstName,
                "lastName": user.lastName,
                "password": user.password,
                "phoneNo": user.phoneNo,
                "dob": user.dob.isoformat() + 'T00:00:00.000Z' if user.dob else None,
                "isAgreeTermsConditions": user.isAgreeTermsConditions,
                "role_id": str(user.role.id) if user.role else None,
                "status": user.status,
                "Islogin_permissions": True,
                "Permissions_DeviceLocation": False,
                "hobby": [],
                "RegistrationType": "Individual",
                "invitedBy": None,
                "created_by": None,
                "updated_by": None,
                "created_at": user.date_joined.isoformat() if user.date_joined else timezone.now().isoformat(),
                "updated_at": timezone.now().isoformat(),
                "ReferralCode": generate_referral_code(user),
                "user_id": None,
                "freeTrialPlan": False
            }

            return Response({
                "success": True,
                "message": "OTP verified successfully",
                "data": {
                    "user": user_data,
                    "accessToken": str(access_token),
                    "refreshToken": str(refresh)
                },
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "message": "Failed to verify OTP",
                "error": str(e),
                "data": None,
                "timestamp": timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)