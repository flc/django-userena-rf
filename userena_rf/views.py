from django.contrib.auth import (
        login as auth_login,
        logout as auth_logout,
        )
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate

from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST
from rest_framework import exceptions

from userena import settings as userena_settings
from userena import signals as userena_signals

from .permissions import IsNotAuthenticated
from .serializers import (
    SignInSerializer,
    ChangePasswordSerializer,
    SignUpSerializer,
    SignUpOnlyEmailSerializer,
    )
from .mixins import SecureRequiredMixin


class SignUpView(SecureRequiredMixin, generics.GenericAPIView):
    allowed_methods = ['post']

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsNotAuthenticated, )
    serializer_class = SignUpSerializer  # overriden in get_serializer_class

    def check_permissions(self, request):
        if userena_settings.USERENA_DISABLE_SIGNUP:
            raise exceptions.PermissionDenied(
                _('Sign up is currently disabled')
                )

        return super(SignUpView, self).check_permissions(request)

    def get_serializer_class(self):
        if userena_settings.USERENA_WITHOUT_USERNAMES:
            return SignUpOnlyEmailSerializer
        return SignUpSerializer

    def post(self, request, format=None):
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.DATA)

        if serializer.is_valid():
            new_user = serializer.instance

            # Send the signup complete signal
            userena_signals.signup_complete.send(sender=None,
                                                 user=new_user)

            # A new signed user should logout the old one.
            if request.user.is_authenticated():
                auth_logout(request)

            signed_in = False
            if (userena_settings.USERENA_SIGNIN_AFTER_SIGNUP and
                not userena_settings.USERENA_ACTIVATION_REQUIRED):
                new_user = authenticate(
                    identification=new_user.email,
                    check_password=False,
                    )
                auth_login(request, new_user)
                userena_signals.account_signin.send(sender=None, user=new_user)
                signed_in = True

            return Response({
                'detail': _('Signed up successfully.'),
                'username': new_user.username,
                'signed_in': signed_in,
                })

        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


class SignInView(SecureRequiredMixin, generics.GenericAPIView):
    allowed_methods = ['post']

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsNotAuthenticated, )
    serializer_class = SignInSerializer

    def set_session_expiry(self, request):
        if request.DATA.get('remember_me'):
            request.session.set_expiry(
                userena_settings.USERENA_REMEMBER_ME_DAYS[1] * 86400
                )
        else:
            request.session.set_expiry(0)

    def post(self, request, format=None):
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.DATA)

        if serializer.is_valid():
            user = serializer.instance
            auth_login(request, user)

            self.set_session_expiry(request)

            # send a signal that a user has signed in
            userena_signals.account_signin.send(sender=None, user=user)

            return Response({
                'detail': _('Signed in successfully.'),
                'username': user.username
                })

        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

    def permission_denied(self, request):
        raise exceptions.PermissionDenied(_("Already authenticated."))


class SignOutView(SecureRequiredMixin, APIView):
    allowed_methods = ['post']

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )

    def post(self, request, format=None):
        auth_logout(request)
        userena_signals.account_signout.send(sender=None, user=request.user)
        return Response({
            'detail': _('Signed out successfully.')
            })


class ChangePasswordView(SecureRequiredMixin, generics.GenericAPIView):
    allowed_methods = ['post']

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    def post(self, request, format=None):
        user = request.user
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.DATA, instance=user)

        if serializer.is_valid():
            serializer.save()  # simply saves user
            userena_signals.password_changed.send(sender=None, user=user)
            return Response({
                    'detail': _('Password has been changed.')
                    })

        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


class CurrentUserView(APIView):
    allowed_methods = ['get']

    def get(self, request, format=None):
        ret = {}
        user = request.user
        if user.is_authenticated():
            ret['username'] = user.username
            ret['email'] = user.email
            ret['first_name'] = user.first_name
            ret['last_name'] = user.last_name
        return Response(ret)
