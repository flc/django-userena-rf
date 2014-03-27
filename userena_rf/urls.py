from django.conf.urls import patterns, url
from django.conf import settings
from django.contrib.auth import views as auth_views

from userena.urls import merged_dict
from userena.compat import auth_views_compat_quirks, password_reset_uid_kwarg
from userena import settings as userena_settings

from . import views


urlpatterns = patterns('',
    url(r'^signin/$',
        views.SignInRememberMeView.as_view(),
        name='signin',
        ),
    url(r'^signout/$',
        views.SignOutView.as_view(),
        name='signout',
        ),
    url(r'^signup/$',
        views.SignUpView.as_view(),
        name='signup',
        ),
    url(r'^password/reset/$',
        views.PasswordResetView.as_view(**{
            'email_template_name': 'userena/emails/password_reset_message.txt',
            }),
        name='password_reset',
        ),
    url(r'^password/reset/confirm/(?P<%s>[0-9A-Za-z_\-]+)/(?P<token>.+)/$' % password_reset_uid_kwarg,
       auth_views.password_reset_confirm,
       merged_dict({'template_name': 'userena/password_reset_confirm_form.html',
                    }, auth_views_compat_quirks['userena_password_reset_confirm']),
       name='userena_password_reset_confirm'),
    url(r'^password/reset/done/$',
       auth_views.password_reset_done,
       {'template_name': 'userena/password_reset_done.html',},
       name='userena_password_reset_done'),
    url(r'^password/reset/confirm/complete/$',
       auth_views.password_reset_complete,
       {'template_name': 'userena/password_reset_complete.html'},
        name='userena_password_reset_complete'),
    url(r'^me/$',
        views.CurrentUserView.as_view(),
        name='current-user',
        ),
)
