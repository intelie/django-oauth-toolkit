from __future__ import absolute_import
from django.conf import settings
from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns(
    '',
    url(r'^authorize/$', views.AuthorizationView.as_view(), name="authorize"),
    url(r'^token/$', views.TokenView.as_view(), name="token"),
)

# Application management views
if settings.OAUTH2_PROVIDER['ENABLE_MANAGEMENT_URLS']:
    urlpatterns += patterns(
        '',
        url(r'^applications/$', views.ApplicationList.as_view(), name="list"),
        url(r'^applications/register/$', views.ApplicationRegistration.as_view(), name="register"),
        url(r'^applications/(?P<pk>\d+)/$', views.ApplicationDetail.as_view(), name="detail"),
        url(r'^applications/(?P<pk>\d+)/delete/$', views.ApplicationDelete.as_view(), name="delete"),
        url(r'^applications/(?P<pk>\d+)/update/$', views.ApplicationUpdate.as_view(), name="update"),
    )
