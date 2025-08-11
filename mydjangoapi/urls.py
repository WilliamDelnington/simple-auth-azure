from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import *

urlpatterns = [
    path("signin", SignInAPIView.as_view(), name="sign-in"),
    path("signup", SignUpAPIView.as_view(), name="sign-up"),
    path("users/<int:userId>/update", UpdateProfileAPIView.as_view(), name="update-profile"),
    path("update-password", UpdatePasswordAPIView.as_view(), name="update-password"),
    path("forgot-password", ForgotPasswordAPIView.as_view(), name="forgot-password"),
    path("reset-password", ResetPasswordAPIView.as_view(), name="reset-password"),
    path("token/refresh", CustomTokenRefreshView.as_view(), name="refresh-token"),
    path("users", UserListView.as_view(), name="users-list"),
    path("users/<int:id>", UserHandleView.as_view(), name="user-handler")
]