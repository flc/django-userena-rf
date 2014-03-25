from django.conf.urls import patterns, url
from django.conf import settings

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
    url(r'^me/$',
        views.CurrentUserView.as_view(),
        name='current-user',
        ),
)
