from django.db import models
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _

from userena.models import UserenaBaseProfile


User = get_user_model()


class Profile(UserenaBaseProfile):
    user = models.OneToOneField(User,
                                unique=True,
                                verbose_name=_('user'),
                                related_name='my_profile')
