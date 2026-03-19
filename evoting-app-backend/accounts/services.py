from django.contrib.auth import get_user_model
from django.db import transaction

from accounts.models import VoterProfile
from audit.services import AuditService
from elections.models import VotingStation

User = get_user_model()


class AuthenticationService:
    def __init__(self):
        self._audit = AuditService()

    def authenticate_admin(self, username, password):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            self._audit.log("LOGIN_FAILED", username, "Invalid admin credentials")
            return None, "Invalid credentials."

        if not user.check_password(password):
            self._audit.log("LOGIN_FAILED", username, "Wrong password")
            return None, "Invalid credentials."

        if not user.is_admin_user:
            self._audit.log("LOGIN_FAILED", username, "Not an admin account")
            return None, "This is not an admin account."

        if not user.is_active:
            self._audit.log("LOGIN_FAILED", username, "Account deactivated")
            return None, "This account has been deactivated."

        self._audit.log("LOGIN", username, "Admin login successful")
        return user, None

    def authenticate_voter(self, voter_card_number, password):
        try:
            profile = VoterProfile.objects.select_related("user").get(
                voter_card_number=voter_card_number
            )
        except VoterProfile.DoesNotExist:
            self._audit.log("LOGIN_FAILED", voter_card_number, "Invalid voter credentials")
            return None, "Invalid voter card number or password."

        user = profile.user

        if not user.check_password(password):
            self._audit.log("LOGIN_FAILED", voter_card_number, "Invalid voter credentials")
            return None, "Invalid voter card number or password."

        if not user.is_active:
            self._audit.log("LOGIN_FAILED", voter_card_number, "Voter account deactivated")
            return None, "This voter account has been deactivated."

        if not user.is_verified:
            self._audit.log("LOGIN_FAILED", voter_card_number, "Voter not verified")
            return None, "Your registration has not been verified yet."

        self._audit.log("LOGIN", voter_card_number, "Voter login successful")
        return user, None


class VoterRegistrationService:
    def __init__(self):
        self._audit = AuditService()

    @transaction.atomic  #  Issue #1 fixed - rolls back user if profile creation fails
    def register(self, validated_data):
        names = validated_data["full_name"].split(" ", 1)
        station = VotingStation.objects.get(pk=validated_data["station_id"])

        user = User.objects.create_user(
            username=validated_data["email"],
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=names[0],
            last_name=names[1] if len(names) > 1 else "",
            role=User.Role.VOTER,
            is_verified=False,
        )

        profile = VoterProfile.objects.create(
            user=user,
            national_id=validated_data["national_id"],
            date_of_birth=validated_data["date_of_birth"],
            gender=validated_data["gender"],
            address=validated_data["address"],
            phone=validated_data["phone"],
            station=station,
        )

        self._audit.log(
            "REGISTER",
            validated_data["full_name"],
            f"New voter registered with card: {profile.voter_card_number}",
        )
        return profile


class AdminManagementService:
    def __init__(self):
        self._audit = AuditService()

    @transaction.atomic
    def create_admin(self, validated_data, created_by):
        names = validated_data["full_name"].split(" ", 1)
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=names[0],
            last_name=names[1] if len(names) > 1 else "",
            role=validated_data["role"],
            is_verified=True,
            is_staff=True,
        )
        self._audit.log(
            "CREATE_ADMIN",
            created_by.username,
            f"Created admin: {user.username} (Role: {user.role})",
        )
        return user

    def deactivate(self, admin_id, deactivated_by):
        try:  # Issue #2 fixed - handle missing admin gracefully
            admin_user = User.objects.get(pk=admin_id)
        except User.DoesNotExist:
            return None, "Admin user not found."

        admin_user.is_active = False
        admin_user.save()
        self._audit.log(
            "DEACTIVATE_ADMIN",
            deactivated_by.username,
            f"Deactivated admin: {admin_user.username}",
        )
        return admin_user, None


class VoterManagementService:
    def __init__(self):
        self._audit = AuditService()

    def verify(self, voter_id, verified_by):
        try:  #  Issue #2 fixed - handle missing voter gracefully
            user = User.objects.get(pk=voter_id)
        except User.DoesNotExist:
            return None, "Voter not found."

        user.is_verified = True
        user.save(update_fields=["is_verified"])
        self._audit.log(
            "VERIFY_VOTER",
            verified_by.username,
            f"Verified voter: {user.get_full_name()}",
        )
        return user, None

    @transaction.atomic  #  Issue #3 fixed - bulk update is now atomic
    def verify_all_pending(self, verified_by):
        unverified = User.objects.filter(is_verified=False)
        count = unverified.update(is_verified=True)
        self._audit.log(
            "VERIFY_ALL_VOTERS",
            verified_by.username,
            f"Verified {count} voters",
        )
        return count

    def deactivate(self, voter_id, deactivated_by):
        try:  #  Issue #2 fixed - handle missing voter gracefully
            user = User.objects.get(pk=voter_id, role=User.Role.VOTER)
        except User.DoesNotExist:
            return None, "Voter not found."

        user.is_active = False
        user.save(update_fields=["is_active"])
        self._audit.log(
            "DEACTIVATE_VOTER",
            deactivated_by.username,
            f"Deactivated voter: {user.get_full_name()}",
        )
        return user, None

    def search(self, query_params):
        qs = User.objects.filter(role=User.Role.VOTER).select_related("voter_profile")

        if name := query_params.get("name"):
            qs = (
                qs.filter(first_name__icontains=name) |
                qs.filter(last_name__icontains=name)
            ).distinct()  #  Issue #4 fixed - prevent duplicate results

        if card := query_params.get("card"):
            qs = qs.filter(voter_profile__voter_card_number=card)
        if nid := query_params.get("national_id"):
            qs = qs.filter(voter_profile__national_id=nid)
        if station_id := query_params.get("station_id"):
            qs = qs.filter(voter_profile__station_id=station_id)

        return qs
