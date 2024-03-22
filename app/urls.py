from django.urls import path,include
from app.views import UserRegistrationView,LoginView,UserProfileView,UserChangePasswordView,SendPasswordResetEmailView,PasswordResetView
urlpatterns = [
    path('register/',UserRegistrationView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('profile/',UserProfileView.as_view(),name='profile'),
    path('changepassword/',UserChangePasswordView.as_view(),name="change password"),
    path('restpassword/',SendPasswordResetEmailView.as_view(),name='resetpassword'),
    path('resetpassword/<str:uidb64>/<str:token>/', PasswordResetView.as_view(), name='reset-password'),

    ]