from django.shortcuts import render
from django.contrib.auth import authenticate
from django.views.generic import ListView
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from .serializer import *
from .models import User

# Create your views here.
class UserListView(ListView):
    model = User
    template_name = "user.html"

class UserHandleView(RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = "id"

class SignUpAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        print(f"Signup request sent. Data: {request.data}")
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            tokens = serializer.get_tokens(user)
            # Prepare response
            print(tokens)
            response = Response({
                'message': 'User created successfully',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'phone_number': user.phone_number,
                    'address': user.address,
                    'location': user.location
                },
                "tokens": tokens
            }, status=status.HTTP_201_CREATED)
            # Set HttpOnly cookies
            # response.set_cookie(
            #     key='access_token',
            #     value=tokens['access'],
            #     httponly=True,
            #     secure=True,  # Use HTTPS in production
            #     samesite='Lax',
            #     max_age=15 * 60  # 15 minutes, matching ACCESS_TOKEN_LIFETIME
            # )
            # response.set_cookie(
            #     key='refresh_token',
            #     value=tokens['refresh'],
            #     httponly=True,
            #     secure=True,
            #     samesite='Lax',
            #     max_age=7 * 24 * 60 * 60  # 7 days, matching REFRESH_TOKEN_LIFETIME
            # )
            return response
        print("Serializer not valid: ", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class SignInAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignInSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.validated_data['user']
            tokens = serializer.get_tokens(user)
            return Response({
                'message': 'Login successful',
                'tokens': tokens,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'phone_number': user.phone_number,
                    'address': user.address,
                    'location': user.location
                }
            }, status=status.HTTP_200_OK)
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UpdateProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, userId):
        try:
            user = User.objects.get(id=userId)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Ensure the requesting user can only update their own profile
        if request.user.id != user.id:
            return Response({'error': 'You are not authorized to update this profile.'}, status=status.HTTP_403_FORBIDDEN)
        
        if not user.check_password(request.data["password"]):
            return Response({'error': 'Invalid password'}, status=status.HTTP_400_BAD_REQUEST)
        
        mapped_data = {
            'first_name': request.data.get('firstName'),
            'last_name': request.data.get('lastName'),
            'phone_number': request.data.get('phoneNumber'),
            'email': request.data.get('email'),
            'address': request.data.get('address'),
            'location': request.data.get('location'),
        }

        serializer = UpdateProfileSerializer(user, data=mapped_data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Profile updated successfully',
                'user': {
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'phone_number': user.phone_number,
                    'address': user.address,
                    'location': user.location
                }
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UpdatePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        mapped_data = {
            "current_password": request.data.get("currentPassword"),
            "new_password": request.data.get("newPassword")
        }
        serializer = UpdatePasswordSerializer(data=mapped_data, context={'request': request})
        if serializer.is_valid():
            new_token = serializer.save()
            return Response({
                'message': 'Password updated successfully',
                'tokens': new_token
            }, status=status.HTTP_200_OK)
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordAPIView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password reset email sent successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordAPIView(APIView):
    def post(self, request):
        mapped_data = {
            "uid": request.data.get("uid"),
            "token": request.data.get("token"),
            "new_password": request.data.get("newPassword")
        }
        serializer = ResetPasswordSerializer(data=mapped_data)
        if serializer.is_valid():
            tokens = serializer.save()
            return Response({
                'message': 'Password reset successfully.',
                'tokens': tokens
            }, status=status.HTTP_200_OK)
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        print(request.data)
        response = super().post(request, *args, **kwargs)
        print(response)
        if response.status_code == status.HTTP_200_OK:
            response.set_cookie(
                key="access_token",
                value=response.data["access"],
                httponly=True,
                secure=True,
                samesite='Lax',
                max_age=15 * 60
            )
            if 'refresh' in response.data:
                response.set_cookie(
                    key="refresh_token",
                    value=response.data["refresh"],
                    httponly=True,
                    secure=True,
                    samesite='Lax',
                    max_age=21 * 24 * 60 * 60
                )
        return response