from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from app.serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer,PasswordResetSerialiser
from django.contrib.auth import authenticate
from app.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
import logging


# Create your views here.

#generate maunally tokens
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token= get_tokens_for_user(user)
            return Response({'token': token, 'msg':'Registration success'},status=status.HTTP_201_CREATED)
       
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user=authenticate(email=email, password=password)
            if user is not None:
                token= get_tokens_for_user(user)
                return Response({'token':token, 'msg':'Login success'},status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors':['Email or password isnt valid']}},status=status.HTTP_404_NOT_FOUND)
            
class UserProfileView(APIView):
    renderer_classes=[UserRenderer]
    permission_classes= [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    renderer_classes=[UserRenderer]
    permission_classes= [IsAuthenticated]
    def post(self, request, format=None):
        seriliazer= UserChangePasswordSerializer(data=request.data, context={'user':request.user})
        if seriliazer.is_valid(raise_exception=True):
            return Response({'msg':'Password is saved'},status=status.HTTP_200_OK)
        return Response(seriliazer.errors,status=status.HTTP_400_BAD_REQUEST)
    
class SendPasswordResetEmailView(APIView):
    renderer_classes=[UserRenderer]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':"Password reset link has been send check your email"},status=status.HTTP_200_OK)
        
logger = logging.getLogger(__name__)
class PasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uidb64, token, format=None):
        try:
            uid = smart_str(urlsafe_base64_decode(uidb64))
            serializer = PasswordResetSerialiser(data=request.data, context={'uid': uid, 'token': token})
            if serializer.is_valid(raise_exception=True):
                return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 
        except Exception as e:
            logger.error(f"An error occurred during password reset: {str(e)}")
            return Response({'error': 'An error occurred during password reset'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
