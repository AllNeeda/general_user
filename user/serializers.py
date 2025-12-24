from rest_framework import serializers
from .models import User, Role, OTP
import secrets
import string
from django.utils import timezone

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'name', 'status']


class UserListSerializer(serializers.ModelSerializer):
    role_id = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'firstName', 'lastName', 'phoneNo', 'dob', 'isAgreeTermsConditions', 
                  'role_id', 'status', 'date_joined']
    
    def generate_referral_code(self, instance):
        """Generate a consistent referral code based on user ID"""
        alphabet = string.ascii_uppercase + string.digits
        # Use a seed based on user ID for consistency
        import hashlib
        seed = str(instance.id).encode()
        hash_obj = hashlib.md5(seed)
        hash_hex = hash_obj.hexdigest()[:10]
        # Convert to alphanumeric
        code = ''.join(alphabet[int(hash_hex[i], 16) % len(alphabet)] for i in range(10))
        return code
    
    def get_role_id(self, obj):
        return str(obj.role.id) if obj.role else None
    
    def get_updated_by(self, instance):
        """Get updated_by user details if available"""
        # Check if updated_by field exists (as ForeignKey to User)
        if hasattr(instance, 'updated_by') and instance.updated_by:
            updated_by_user = instance.updated_by
            return {
                '_id': str(updated_by_user.id),
                'firstName': updated_by_user.firstName,
                'lastName': updated_by_user.lastName,
                'phoneNo': updated_by_user.phoneNo,
                'user_id': None,  # Can be set based on your logic
                'Email': getattr(updated_by_user, 'email', None)  # AbstractUser has email field
            }
        return None
    
    def to_representation(self, instance):
        """Customize the response to match expected format"""
        representation = {
            '_id': str(instance.id),  # Use _id instead of id
            'firstName': instance.firstName,
            'lastName': instance.lastName,
            'phoneNo': instance.phoneNo,
            'dob': instance.dob.isoformat() + 'T00:00:00.000Z' if instance.dob else None,
            'isAgreeTermsConditions': instance.isAgreeTermsConditions,
            'role_id': str(instance.role.id) if instance.role else None,
            'status': instance.status,
        }
        
        # Add default values for fields not in the model
        representation['language_id'] = None
        representation['country_id'] = None
        representation['state_id'] = None
        representation['city_id'] = None
        representation['Islogin_permissions'] = True
        representation['Permissions_DeviceLocation'] = False
        representation['freeTrialPlan'] = False
        representation['hobby'] = []
        representation['RegistrationType'] = "Individual"
        representation['invitedBy'] = None
        representation['created_by'] = None
        representation['updated_by'] = self.get_updated_by(instance)
        
        # Format dates - use date_joined for both created_at and updated_at
        if instance.date_joined:
            representation['created_at'] = instance.date_joined.isoformat()
            representation['updated_at'] = instance.date_joined.isoformat()
        else:
            representation['created_at'] = timezone.now().isoformat()
            representation['updated_at'] = timezone.now().isoformat()
        
        # Generate referral code (consistent based on user ID)
        representation['ReferralCode'] = self.generate_referral_code(instance)
        representation['user_id'] = None  # Can be set based on your logic
        
        return representation


class CreateSerializer(serializers.ModelSerializer):
    role_id = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(),
        write_only=True,
        source='role',
        required=True
    )
    password = serializers.CharField(read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'firstName', 'lastName', 'phoneNo', 'dob', 'isAgreeTermsConditions', 'role_id', 'status', 'password']
        read_only_fields = ['password']

    def generate_password(self):
        """Generate a random secure password"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(16))
        return password

    def generate_referral_code(self):
        """Generate a random referral code"""
        alphabet = string.ascii_uppercase + string.digits
        return ''.join(secrets.choice(alphabet) for i in range(10))

    def create(self, validated_data):
        # Generate password in backend
        password = self.generate_password()
        phoneNo = validated_data.pop('phoneNo')
        
        user = User.objects.create_user(
            phoneNo,
            password=password,
            **validated_data
        )
        
        # Store the plain password temporarily to include in response
        user._plain_password = password
        return user

    def to_representation(self, instance):
        """Customize the response to include all expected fields"""
        # Get base representation
        representation = {
            'id': str(instance.id),
            'firstName': instance.firstName,
            'lastName': instance.lastName,
            'phoneNo': instance.phoneNo,
            'dob': instance.dob.isoformat() + 'T00:00:00.000Z' if instance.dob else None,
            'isAgreeTermsConditions': instance.isAgreeTermsConditions,
            'status': instance.status,
        }
        
        # Add password (hashed) to response
        representation['password'] = instance.password
        
        # Add role_id (UUID will be returned as string)
        representation['role_id'] = str(instance.role.id) if instance.role else None
        
        # Add default values for fields not in the model
        representation['language_id'] = None
        representation['country_id'] = None
        representation['state_id'] = None
        representation['city_id'] = None
        representation['Islogin_permissions'] = True
        representation['Permissions_DeviceLocation'] = False
        representation['freeTrialPlan'] = False
        representation['hobby'] = []
        representation['RegistrationType'] = "Individual"
        representation['passwordChangeOTPVerified'] = False
        representation['invitedBy'] = None
        representation['created_by'] = None
        representation['updated_by'] = None
        representation['_id'] = str(instance.id)  # Use UUID as _id
        representation['created_at'] = timezone.now().isoformat()
        representation['updated_at'] = timezone.now().isoformat()
        representation['ReferralCode'] = self.generate_referral_code()
        representation['user_id'] = None  # Can be set based on your logic
        
        return representation


     

class OTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTP
        fields = "__all__"
        read_only_fields = [ 'otp', 'created_at', 'is_verified']


class VerifySerializer(serializers.ModelSerializer):
    class Meta:
        model = OTP
        fields = "__all__"
        read_only_fields = ['created_at', 'is_verified']

   
