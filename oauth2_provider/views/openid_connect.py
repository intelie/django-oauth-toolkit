import json
from django.http import HttpResponse

from .generic import ProtectedResourceView


class UserInfoView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        user = request.resource_owner

        claims = {
            'sub': user.username,
            'given_name': user.first_name,
            'family_name': user.last_name,
            'preferred_username': user.username,
            'email': user.email,
            'is_superuser': getattr(user, 'is_superuser', False),
            'is_staff': getattr(user, 'is_staff', False),
        }

        return HttpResponse(json.dumps(claims))
