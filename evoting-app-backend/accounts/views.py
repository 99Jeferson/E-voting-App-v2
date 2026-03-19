from django.contrib.auth import get_user_model
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.permissions import IsAdminUser, IsSuperAdmin
from accounts.serializers import (
    AdminCreateSerializer,
    AdminListSerializer,
    AdminLoginSerializer,
    ChangePasswordSerializer,
    UserSerializer,
    VoterListSerializer,
    VoterLoginSerializer,
    VoterProfileSerializer,
    VoterRegistrationSerializer,
)
from accounts.services import (
    AdminManagementService,
    AuthenticationService,
    VoterManagementService,
    VoterRegistrationService,
)

User = get_user_model()


class AdminLoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = AdminLoginSerializer

    def post(self, request):
        serializer = AdminLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = AuthenticationService()
        user, error = service.authenticate_admin(
            serializer.validated_data["username"],
            serializer.validated_data["password"],
        )

        if error:
            return Response({"detail": error}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "username": user.username,
                "full_name": user.get_full_name(),
                "role": user.role,
            },
        })


class VoterLoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = VoterLoginSerializer

    def post(self, request):
        serializer = VoterLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = AuthenticationService()
        user, error = service.authenticate_voter(
            serializer.validated_data["voter_card_number"],
            serializer.validated_data["password"],
        )

        if error:
            return Response({"detail": error}, status=status.HTTP_401_UNAUTHORIZED)

        # ✅ Issue #1 fixed - guard against missing voter profile
        try:
            voter_card_number = user.voter_profile.voter_card_number
        except User.voter_profile.RelatedObjectDoesNotExist:
            return Response(
                {"detail": "Voter profile not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "full_name": user.get_full_name(),
                "voter_card_number": voter_card_number,
                "role": user.role,
            },
        })


class VoterRegistrationView(APIView):
    permission_classes = [AllowAny]
    serializer_class = VoterRegistrationSerializer

    def post(self, request):
        serializer = VoterRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # ✅ Issue #6 fixed - handle exceptions from service.register cleanly
        try:
            service = VoterRegistrationService()
            profile = service.register(serializer.validated_data)
        except Exception as e:
            return Response(
                {"detail": "Registration failed. Please try again."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "detail": "Registration successful. Pending admin verification.",
                "voter_card_number": profile.voter_card_number,
            },
            status=status.HTTP_201_CREATED,
        )


class VoterProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # ✅ Issue #2 fixed - guard against missing voter profile
        try:
            profile = request.user.voter_profile
        except Exception:
            return Response(
                {"detail": "Voter profile not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = VoterProfileSerializer(profile)
        return Response(serializer.data)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not request.user.check_password(serializer.validated_data["current_password"]):
            return Response(
                {"detail": "Incorrect current password."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save()

        return Response({"detail": "Password changed successfully."})


class VoterListView(generics.ListAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = VoterListSerializer

    def get_queryset(self):
        service = VoterManagementService()
        return service.search(self.request.query_params)


class VoterVerifyView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, pk):
        service = VoterManagementService()
        # ✅ Issue #3 fixed - unpack tuple and handle error
        user, error = service.verify(pk, request.user)
        if error:
            return Response({"detail": error}, status=status.HTTP_404_NOT_FOUND)
        return Response({"detail": "Voter verified successfully."})


class VoterVerifyAllView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        service = VoterManagementService()
        count = service.verify_all_pending(request.user)
        return Response({"detail": f"{count} voters verified."})


class VoterDeactivateView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, pk):
        service = VoterManagementService()
        # ✅ Issue #4 fixed - use tuple unpacking instead of try/except
        user, error = service.deactivate(pk, request.user)
        if error:
            return Response({"detail": error}, status=status.HTTP_404_NOT_FOUND)
        return Response({"detail": "Voter deactivated."})


class AdminListView(generics.ListAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = AdminListSerializer

    def get_queryset(self):
        return User.objects.filter(role__in=User.ADMIN_ROLES).order_by("-date_joined")


class AdminCreateView(APIView):
    permission_classes = [IsSuperAdmin]
    serializer_class = AdminCreateSerializer

    def post(self, request):
        serializer = AdminCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = AdminManagementService()
        admin_user = service.create_admin(serializer.validated_data, request.user)

        return Response(
            {
                "detail": f"Admin '{admin_user.username}' created with role: {admin_user.role}",
                "id": admin_user.id,
            },
            status=status.HTTP_201_CREATED,
        )


class AdminDeactivateView(APIView):
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk):
        if pk == request.user.pk:
            return Response(
                {"detail": "Cannot deactivate your own account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        service = AdminManagementService()
        # ✅ Issue #5 fixed - unpack tuple and handle error
        admin_user, error = service.deactivate(pk, request.user)
        if error:
            return Response({"detail": error}, status=status.HTTP_404_NOT_FOUND)
        return Response({"detail": "Admin deactivated."})
