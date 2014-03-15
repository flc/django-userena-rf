from django.conf import settings


USERNAME_RE = getattr(settings, 'USERENA_USERNAME_RE', r'^[\.\w]+$')
PASSWORD_MIN_LENGTH = getattr(settings, 'USERENA_PASSWORD_MIN_LENGTH', 6)
