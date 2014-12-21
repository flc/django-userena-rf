import random
try:
    from hashlib import sha1 as sha_constructor
except ImportError:
    from django.utils.hashcompat import sha_constructor

from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate, get_user_model
from django.conf import settings
from django.forms import widgets

from userena.models import UserenaSignup
from userena import settings as userena_settings

from rest_framework import serializers
from rest_framework.reverse import reverse

from .settings import USERNAME_RE, PASSWORD_MIN_LENGTH


User = get_user_model()
PASSWORD_MAX_LENGTH = User._meta.get_field('password').max_length


class SignInSerializer(serializers.Serializer):
    identification = serializers.CharField(
        max_length=User._meta.get_field('email').max_length
        )
    password = serializers.CharField(
        style={'input_type': 'password'},
        )

    def validate(self, attrs):
        user = authenticate(
            identification=attrs.get('identification'),
            password=attrs.get('password'),
            )

        if user is not None:
            if user.is_active:
                self.user = user
            else:
                raise serializers.ValidationError(
                    _("The account is currently inactive.")
                    )
        else:
            error = _(
                "Invalid credentials. "
                "Note that both fields are case-sensitive."
                )
            raise serializers.ValidationError(error)

        return attrs


class SignInRememberMeSerializer(SignInSerializer):
    remember_me = serializers.BooleanField(
        default=False,
        )


class PasswordSetSerializer(serializers.Serializer):
    """
    A serializer that lets a user change set his/her password without entering the
    old password.
    """
    default_error_messages = dict(serializers.Serializer.default_error_messages, **{
        u'password_mismatch': _("The two password fields didn't match."),
    })

    password1 = serializers.CharField(
        label=_("New password"),
        style={'input_type': 'password'},
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
        )
    password2 = serializers.CharField(
        label=_("New password (again)"),
        style={'input_type': 'password'},
        )

    def validate(self, attrs):
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        if password1 and password2:
            if password1 != password2:
                raise serializers.ValidationError({
                    'password2': self.error_messages['password_mismatch']
                    })
        return attrs

    def update(self, instance, validated_data):
        instance.set_password(validated_data.get('password1'))
        instance.save()
        return instance

    def create(self, validated_data):
        assert False, 'Only update is allowed'


class PasswordChangeSerializer(PasswordSetSerializer):
    """
    A serializer that lets a user change his/her password by entering
    their current password.
    """
    default_error_messages = dict(PasswordSetSerializer.default_error_messages, **{
        u'password_incorrect': _("Your current password was entered incorrectly. "
                                "Please enter it again."),
    })

    current_password = serializers.CharField(
        label=_("Current Password"),
        style={'input_type': 'password'},
        )

    def validate_current_password(self, value):
        user = self.instance
        if not user.check_password(value):
            raise serializers.ValidationError(
                self.error_messages['password_incorrect']
                )
        return value


class SignUpSerializer(serializers.Serializer):
    username = serializers.RegexField(
        regex=USERNAME_RE,
        max_length=User._meta.get_field("username").max_length,
        min_length=3,
        label=_("Username"),
        error_messages={
            'invalid': _('Username must contain only letters, numbers, dots and underscores.')
            },
        )
    email = serializers.EmailField(
        label=_("Email"),
        max_length=User._meta.get_field('email').max_length,
    )
    password1 = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
        )
    password2 = serializers.CharField(
        label=_("Password Again"),
        style={'input_type': 'password'},
        # min_length=PASSWORD_MIN_LENGTH,
        # max_length=PASSWORD_MAX_LENGTH,
        )

    def validate_username(self, value):
        username = value
        try:
            user = User.objects.get(username__iexact=username)
        except User.DoesNotExist:
            pass
        else:
            query = UserenaSignup.objects\
                .filter(user__username__iexact=username)\
                .exclude(activation_key=userena_settings.USERENA_ACTIVATED)
            if (userena_settings.USERENA_ACTIVATION_REQUIRED and
                query.exists()):
                raise serializers.ValidationError(
                    _('This username is already taken but not confirmed. '
                      'Please check your email for verification steps.')
                    )
            raise serializers.ValidationError(
                    _('This username is already taken.')
                    )
        if username.lower() in userena_settings.USERENA_FORBIDDEN_USERNAMES:
            raise serializers.ValidationError(
                    _('This username is not allowed.')
                    )
        return value

    def validate_email(self, value):
        """ Validate that the e-mail address is unique. """
        email = value

        if User.objects.filter(email__iexact=email).exists():
            query = UserenaSignup.objects\
                .filter(user__email__iexact=email)\
                .exclude(activation_key=userena_settings.USERENA_ACTIVATED)
            if (userena_settings.USERENA_ACTIVATION_REQUIRED and
                query.exists()):
                raise serializers.ValidationError(
                    _('This email is already in use but not confirmed. '
                      'Please check your email for verification steps.')
                    )
            raise serializers.ValidationError(
                _('This email is already in use. '
                  'Please supply a different email.')
                )

        return value

    def validate(self, attrs):
        """
        Validates that the values entered into the two password fields match.
        Note that an error here will end up in ``non_field_errors()`` because
        it doesn't apply to a single field.
        """
        if 'password1' in attrs and 'password2' in attrs:
            if attrs['password1'] != attrs['password2']:
                raise serializers.ValidationError(
                    _('The two password fields didn\'t match.')
                    )
        return attrs

    def create_user(self, username, email, password):
        return UserenaSignup.objects.create_user(
            username,
            email,
            password,
            active=not userena_settings.USERENA_ACTIVATION_REQUIRED,
            send_email=userena_settings.USERENA_ACTIVATION_REQUIRED,
            )

    def update(self, instance, validated_data):
        assert False, 'Cannot update users with SignUpSerializer'

    def create(self, validated_data):
        username, email, password = (
            validated_data['username'],
            validated_data['email'],
            validated_data['password1'],
            )

        user = self.create_user(username, email, password)
        self.user = user
        return user


class SignUpOnlyEmailSerializer(SignUpSerializer):

    def construct_username(self):
        """ Generate a random username"""
        while True:
            username = sha_constructor(str(random.random())).hexdigest()[:5]
            if not User.objects.get(username__iexact=username).exists():
                return username

    def create(self, validated_data):
        validated_data['username'] = self.construct_username()
        return super(SignUpOnlyEmailSerializer, self).create(attrs, validated_data)


class SignUpTosSerializerMixin(object):
    tos = serializers.BooleanField(
        label=_('I have read and agree to the Terms of Service'),
        error_messages={'required': _('You must agree to the terms to register.')}
        )


class SignUpTosSerializer(SignUpTosSerializerMixin, SignUpSerializer):
    pass


class SignUpOnlyEmailTosSerializer(SignUpTosSerializerMixin, SignUpOnlyEmailSerializer):
    pass


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class EmailChangeSerializer(serializers.Serializer):
    default_error_messages = dict(serializers.Serializer.default_error_messages, **{
        u'already_known': _(u"You're already known under this email."),
        u'already_in_use': _(u"This email is already in use. Please supply a different email.")
    })

    email = serializers.EmailField(
        label=_("New email"),
        max_length=User._meta.get_field('email').max_length,
    )

    def validate_email(self, value):
        """ Validate that the email is not already registered with another user """
        user = self.instance
        email = value

        if email.lower() == user.email:
            raise serializers.ValidationError(self.error_messages['already_known'])

        query = User.objects.filter(email__iexact=email)\
                            .exclude(email__iexact=user.email)
        if query.exists():
            raise serializers.ValidationError(self.error_messages['already_in_use'])

        return value

    def update(self, instance, validated_data):
        """
        Save method calls :func:`user.change_email()` method which sends out an
        email with an verification key to verify and with it enable this new
        email address.
        """
        user = instance
        email = validated_data['email']
        user.userena_signup.change_email(email)
        return instance

    def create(self, validated_data):
        assert False, 'Only update is allowed'


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name', 'last_name')

