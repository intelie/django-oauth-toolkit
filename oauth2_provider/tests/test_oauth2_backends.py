from django.test import TestCase, RequestFactory
import json

from ..backends import get_oauthlib_core
from ..compat import urlparse, parse_qs, urlencode, get_user_model
from django.core.urlresolvers import reverse
from ..models import get_application_model, Grant, AccessToken
from ..settings import oauth2_settings
from .test_utils import TestCaseUtils

Application = get_application_model()
UserModel = get_user_model()


class TestOAuthLibCore(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_validate_authorization_request_unsafe_query(self):
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + "a_casual_token",
        }
        request = self.factory.get("/fake-resource?next=/fake", **auth_headers)

        oauthlib_core = get_oauthlib_core()
        oauthlib_core.verify_request(request, scopes=[])


class TestOpenIDConnectServer(TestCaseUtils, TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = UserModel.objects.create_user('test_user', 'test@user.com', '123456')

        self.application = Application(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.application.save()

        oauth2_settings.SCOPES = {
            'openid': 'OpenID Connect',
            'read': 'Read',
            'write': 'Write'
        }

    def tearDown(self):
        self.application.delete()
        self.user.delete()

    def get_auth(self):
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'openid read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        return query_dict['code'].pop()

    def test_basic_auth(self):
        self.client.login(username='test_user', password='123456')
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id,
                self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'),
                data=token_request_data, **auth_headers)

        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode('utf-8'))

        self.assertIn('id_token', content)
