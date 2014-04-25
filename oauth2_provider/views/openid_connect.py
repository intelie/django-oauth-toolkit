import json
from django.http import HttpResponse

from .generic import ProtectedResourceView


class UserInfoView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        claims = {
            'sub': request.user.username,
            'given_name': request.user.first_name,
            'family_name': request.user.last_name,
            'preferred_username': request.user.username,
            'email': request.user.email
        }

        return HttpResponse(json.dumps(claims))
