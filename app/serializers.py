from rest_framework import serializers
from app.models import CustomUser
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import ValidationError
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model=CustomUser
        fields = ['email', 'name', 'password','password2' ]
        extra_kwargs={
            'password':{'write_only':True}
        }

#validation of passwords 
    def validate(self,attrs):
        password= attrs.get('password')
        password2= attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Passwords doesn't match")
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError(e.message)
        return attrs

    def create(self,validate_data):
        email = validate_data.get("email")
        name = validate_data.get("name")
        password = validate_data.get("password")
        user = CustomUser.objects.create_user(email, name, password)

        return  user
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = CustomUser
        fields = ['email', 'password']
    
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'name']
        
class UserChangePasswordSerializer(serializers.Serializer):
    password= serializers.CharField(max_length=255, style= {'input_type':'password'}, write_only=True)
    password2= serializers.CharField(max_length=255, style= {'input_type':'password'}, write_only=True)
    class Meta:
        fields=['password','password2']
    def validate(self,attrs):
        password= attrs.get('password')
        password2=attrs.get('password2')
        user= self.context.get('user')
        if password != password2: 
            raise serializers.ValidationError("Password and confirm password dont match")
        user.set_password(password)
        user.save()

        return super().validate(attrs)
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email= serializers.EmailField(max_length=255)
    class Meta:
        fields=['email']
    def validate(self,attrs):
        email= attrs.get('email')
        if CustomUser.objects.filter(email=email).exists():
            user= CustomUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded uid',uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Password Reset Token", token)
            link = 'http://localhost:8000/api/user/resetpassword/'+uid+'/'+token
            print('Password Reset Link',link)
            body= 'TO reset password click following your password'+ link
            data={
                'subject':'Reset your password',
                'body':body,
                'email_to':user.email

            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationError('Your email isnt registered')
        
class  PasswordResetSerialiser(serializers.Serializer):
    password= serializers.CharField(max_length=255, style= {'input_type':'password'}, write_only=True)
    password2= serializers.CharField(max_length=255, style= {'input_type':'password'}, write_only=True)
    class Meta:
        fields=['password','password2']
    def validate(self,attrs):
       try:
            password= attrs.get('password')
            password2=attrs.get('password2')
            uidb64 = self.context.get('uidb64')  # Update variable names to match
            token = self.context.get('token')  
            if password != password2: 
                raise serializers.ValidationError("Password and confirm password dont match")
            id= smart_str(urlsafe_base64_decode(uidb64))
            user=CustomUser.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError("Token isnt valid or expired")  
            user.set_password(password)
            user.save()
            return attrs
       except DjangoUnicodeDecodeError as identifier:
           PasswordResetTokenGenerator().check_token(user,token)
           raise ValidationError("Token isnt valid or expired")
       

        