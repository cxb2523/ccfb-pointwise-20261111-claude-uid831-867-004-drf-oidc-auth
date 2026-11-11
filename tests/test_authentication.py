import base64
import json
import sys
import time

from joserfc import jwt as joserfc_jwt
from joserfc.errors import BadSignatureError, DecodeError
from joserfc.jwk import RSAKey
from django.http import HttpResponse
from django.test import TestCase
from django.urls import re_path as url
from requests.models import Response
from oidc_auth.authentication import (BearerTokenAuthentication,
                                      JSONWebTokenAuthentication)
from oidc_auth.test import AuthenticationTestCaseMixin, key, make_id_token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

if sys.version_info > (3,):
    long = int
else:
    class ConnectionError(OSError):
        pass

try:
    from unittest.mock import Mock, PropertyMock, patch
except ImportError:
    from mock import Mock, PropertyMock, patch


class MockView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (
        JSONWebTokenAuthentication,
        BearerTokenAuthentication
    )

    def get(self, request):
        return HttpResponse('a')


urlpatterns = [
    url(r'^test/$', MockView.as_view(), name="testview")
]


class TestBearerAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def setUp(self):
        super(TestBearerAuthentication, self).setUp()
        self.openid_configuration = {
            'issuer': 'http://accounts.example.com/dex',
            'authorization_endpoint': 'http://accounts.example.com/dex/auth',
            'token_endpoint': 'http://accounts.example.com/dex/token',
            'jwks_uri': 'http://accounts.example.com/dex/keys',
            'response_types_supported': ['code'],
            'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': ['RS256'],
            'scopes_supported': ['openid', 'email', 'groups', 'profile', 'offline_access'],
            'token_endpoint_auth_methods_supported': ['client_secret_basic'],
            'claims_supported': [
                'aud', 'email', 'email_verified', 'exp', 'iat', 'iss', 'locale',
                'name', 'sub'
            ],
            'userinfo_endpoint': 'http://sellers.example.com/v1/sellers/'
        }

    def test_using_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.user.username})
        auth = 'Bearer abcdefg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.content.decode(), 'a')
        self.assertEqual(resp.status_code, 200)
        self.mock_get.assert_called_with(
            'http://example.com/userinfo', headers={'Authorization': auth})

    def test_cache_of_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.user.username})
        auth = 'Bearer egergerg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

        # Token expires, but validity is cached
        self.responder.set_response('http://example.com/userinfo', "", 401)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_using_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/userinfo', "", 401)
        auth = 'Bearer hjikasdf'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_cache_of_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/userinfo', "", 401)
        auth = 'Bearer feegrgeregreg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

        # Token becomes valid
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.user.username})
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_using_malformed_bearer_token(self):
        auth = 'Bearer abc def'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_using_missing_bearer_token(self):
        auth = 'Bearer'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_using_inaccessible_userinfo_endpoint(self):
        self.mock_get.side_effect = ConnectionError
        auth = 'Bearer'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_get_user_info_endpoint(self):
        with patch('oidc_auth.authentication.BaseOidcAuthentication.oidc_config', new_callable=PropertyMock) as oidc_config_mock:
            oidc_config_mock.return_value = self.openid_configuration
            authentication = BearerTokenAuthentication()
            response_mock = Mock(return_value=Mock(status_code=200,
                                                   json=Mock(return_value={}),
                                                   raise_for_status=Mock(return_value=None)))
            with patch('oidc_auth.authentication.requests.get', response_mock):
                result = authentication.get_userinfo(b'token')
                assert result == {}

    def test_get_user_info_endpoint_with_missing_field(self):
        self.openid_configuration.pop('userinfo_endpoint')
        with patch('oidc_auth.authentication.BaseOidcAuthentication.oidc_config', new_callable=PropertyMock) as oidc_config_mock:
            oidc_config_mock.return_value = self.openid_configuration
            authentication = BearerTokenAuthentication()
            with self.assertRaisesMessage(AuthenticationFailed, 'userinfo_endpoint'):
                authentication.get_userinfo(b'faketoken')


class TestJWTAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def setUp(self):
        super(TestJWTAuthentication, self).setUp()
        # Serve the JWKS from a mutable key list so tests can simulate key
        # rotation; the mock also counts fetches for cache assertions.
        self.jwks_keys = [key.as_dict()]
        self.jwks_request = self.patch('oidc_auth.authentication.request')
        self.jwks_request.side_effect = self.fake_jwks_request

    def fake_jwks_request(self, *args, **kwargs):
        response = Response()
        response._content = json.dumps({'keys': self.jwks_keys}).encode('utf-8')
        response.status_code = 200
        return response

    def make_signed_token(self, signing_key, **claims):
        payload = dict(
            iss='http://example.com',
            aud='you',
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            sub=str(self.user.username),
        )
        payload.update(claims)
        token = joserfc_jwt.encode(
            {'alg': 'RS256', 'kid': signing_key.as_dict()['kid']},
            payload, signing_key)
        return token.decode('ascii') if isinstance(token, bytes) else token

    def make_token(self, header, payload=None, key=None):
        payload = payload or dict(
            iss='http://example.com',
            aud='you',
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            sub=str(self.user.username),
        )
        if key is not None:
            return joserfc_jwt.encode(header, payload, key).encode('ascii')
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(header).encode('utf-8')).rstrip(b'=')
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')).rstrip(b'=')
        return b'.'.join([encoded_header, encoded_payload, b''])

    def test_using_valid_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content.decode(), 'a')

    def test_without_jwt(self):
        resp = self.client.get('/test/')
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_jwt(self):
        auth = 'JWT e30='
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_auth_header(self):
        auth = 'Bearer 12345'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_expired_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, exp=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_old_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, iat=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_issuer(self):
        auth = 'JWT ' + \
               make_id_token(self.user.username, iss='http://something.com')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_audience(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud='somebody')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_too_new_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, nbf=999999999999)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_unknown_subject(self):
        auth = 'JWT ' + make_id_token(self.user.username + 'x')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud=['you', 'me'])
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_with_invalid_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud=['we', 'me'])
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_multiple_audiences_and_authorized_party(self):
        auth = 'JWT ' + \
               make_id_token(self.user.username, aud=['you', 'me'], azp='you')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_with_invalid_signature(self):
        auth = 'JWT ' + make_id_token(self.user.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth + 'x')
        self.assertEqual(resp.status_code, 401)

    def test_with_alg_none_and_empty_signature(self):
        auth = 'JWT ' + self.make_token(
            {'alg': 'none', 'typ': 'JWT'}).decode('ascii')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_alg_none_and_garbage_signature(self):
        token = self.make_token({'alg': 'none', 'typ': 'JWT'})
        auth = 'JWT ' + (token + b'Z2FyYmFnZQ==').decode('ascii')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_hs256_algorithm(self):
        auth = 'JWT ' + self.make_token(
            {'alg': 'HS256', 'typ': 'JWT'}).decode('ascii')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_malformed_jwt_header(self):
        header = base64.urlsafe_b64encode(b'not-json').rstrip(b'=')
        payload = base64.urlsafe_b64encode(b'{}').rstrip(b'=')
        auth = 'JWT ' + (header + b'.' + payload + b'.').decode('ascii')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_non_object_jwt_header(self):
        for header in (b'[]', b'"x"', b'5', b'null'):
            encoded_header = base64.urlsafe_b64encode(header).rstrip(b'=')
            token = encoded_header + b'.' + base64.urlsafe_b64encode(b'{}').rstrip(b'=') + b'.'
            resp = self.client.get(
                '/test/', HTTP_AUTHORIZATION='JWT ' + token.decode('ascii'))
            self.assertEqual(resp.status_code, 401)

    def test_with_unknown_kid(self):
        token = self.make_token(
            {'alg': 'RS256', 'typ': 'JWT', 'kid': 'unknown'}, key=key)
        resp = self.client.get(
            '/test/', HTTP_AUTHORIZATION='JWT ' + token.decode('ascii'))
        self.assertEqual(resp.status_code, 401)

    def test_jwt_algorithms_setting_is_configurable(self):
        from joserfc.jwk import OctKey
        from oidc_auth.settings import api_settings
        hs256_key = OctKey.generate_key()
        self.patch(
            'oidc_auth.authentication.JSONWebTokenAuthentication.jwks_data',
            return_value={'keys': [hs256_key.as_dict()]})
        authentication = JSONWebTokenAuthentication()
        token = joserfc_jwt.encode(
            {'alg': 'HS256', 'typ': 'JWT'},
            dict(iss='http://example.com', aud='you',
                 exp=int(time.time()) + 3600, iat=int(time.time()),
                 sub=str(self.user.username)),
            hs256_key).encode('ascii')

        with patch('oidc_auth.authentication.api_settings.JWT_ALGORITHMS', ('RS256',)):
            self.assertRaises(
                AuthenticationFailed, authentication.decode_jwt, token)

        with patch('oidc_auth.authentication.api_settings.JWT_ALGORITHMS', ('HS256',)):
            claims = authentication.decode_jwt(token)
            self.assertEqual(claims['sub'], str(self.user.username))


    @patch('oidc_auth.authentication.jwt.decode')
    @patch('oidc_auth.authentication.logger')
    def test_decode_jwt_logs_exception_message_when_decode_throws_exception(
        self,
        logger_mock, decode
    ):
        auth = 'JWT ' + make_id_token(self.user.username)
        decode.side_effect = DecodeError, BadSignatureError

        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)

        self.assertEqual(resp.status_code, 401)
        logger_mock.exception.assert_called_once_with(
            'JWT authentication failed [trace_id=%s]: %s', '-', 'undecodable JWT')

    @patch('oidc_auth.authentication.logger')
    def test_failure_log_contains_trace_id(self, logger_mock):
        auth = 'JWT ' + make_id_token(self.user.username, exp=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth,
                               HTTP_X_REQUEST_ID='trace-abc-123')
        self.assertEqual(resp.status_code, 401)
        logger_mock.exception.assert_called_once_with(
            'JWT authentication failed [trace_id=%s]: %s',
            'trace-abc-123', 'JWT has expired')

    def test_expired_jwt_returns_401_with_rfc6750_header(self):
        auth = 'JWT ' + make_id_token(self.user.username, exp=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)
        self.assertIn('Bearer realm="api"', resp['WWW-Authenticate'])
        self.assertIn('error="invalid_token"', resp['WWW-Authenticate'])
        self.assertIn('error_description=', resp['WWW-Authenticate'])

    def test_malformed_header_returns_invalid_request_error(self):
        resp = self.client.get('/test/', HTTP_AUTHORIZATION='JWT')
        self.assertEqual(resp.status_code, 401)
        self.assertIn('error="invalid_request"', resp['WWW-Authenticate'])

    def test_error_response_does_not_leak_claims(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud='somebody')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)
        # Neither the claim value nor joserfc internals may leak into the body
        self.assertNotIn('somebody', resp.content.decode())
        self.assertNotIn('invalid_claim', resp.content.decode())
        self.assertNotIn('aud', resp.content.decode())

    def test_error_response_does_not_leak_key_material(self):
        other_key = RSAKey.generate_key(auto_kid=True)
        token = self.make_signed_token(other_key)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION='JWT ' + token)
        self.assertEqual(resp.status_code, 401)
        kid = other_key.as_dict()['kid']
        self.assertNotIn(kid, resp.content.decode())
        self.assertNotIn(key.as_dict()['n'], resp.content.decode())

    def test_with_token_signed_by_unknown_key(self):
        other_key = RSAKey.generate_key(auto_kid=True)
        auth = 'JWT ' + self.make_signed_token(other_key)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)
        self.assertIn('error="invalid_token"', resp['WWW-Authenticate'])

    def test_with_invalid_signature_same_kid(self):
        # Token signed with an independent private key but referencing the
        # real key id: exercises the BadSignatureError path.
        other_key = RSAKey.generate_key(auto_kid=True)
        forged_key_dict = other_key.as_dict(private=True)
        forged_key_dict['kid'] = key.as_dict()['kid']
        forged_key = RSAKey.import_key(forged_key_dict)
        auth = 'JWT ' + self.make_signed_token(forged_key)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_invalid_signature_does_not_bust_jwks_cache(self):
        # A flood of tokens with unknown keys must not hammer the IdP:
        # the forced JWKS refresh is rate-limited by a lock.
        other_key = RSAKey.generate_key(auto_kid=True)
        auth = 'JWT ' + self.make_signed_token(other_key)
        for _ in range(3):
            resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
            self.assertEqual(resp.status_code, 401)
        # 1 initial fetch + 1 rate-limited refresh, no matter how many
        # invalid tokens are thrown at the endpoint.
        self.assertEqual(self.jwks_request.call_count, 2)

    def test_key_rotation(self):
        # Valid token signed with the current key populates the JWKS cache
        old_token = make_id_token(self.user.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION='JWT ' + old_token)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.jwks_request.call_count, 1)

        # IdP rotates its signing key and publishes old + new keys
        new_key = RSAKey.generate_key(auto_kid=True)
        self.jwks_keys.append(new_key.as_dict())

        # A token signed with the new key must not be rejected just because
        # the cache still holds only the old key: it triggers a refresh.
        new_token = self.make_signed_token(new_key)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION='JWT ' + new_token)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.jwks_request.call_count, 2)

        # After the refresh, tokens signed with the old key still pass
        resp = self.client.get('/test/', HTTP_AUTHORIZATION='JWT ' + old_token)
        self.assertEqual(resp.status_code, 200)

        # Tokens signed with an unrelated key are still rejected with 401
        # (and do not trigger another fetch thanks to the refresh lock)
        other_key = RSAKey.generate_key(auto_kid=True)
        auth = 'JWT ' + self.make_signed_token(other_key)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.jwks_request.call_count, 2)

    def test_with_non_ascii_jwt(self):
        # Undecodable bytes must yield a 401, not bubble up as a 500
        authentication = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed):
            authentication.decode_jwt('üñïçø∂é'.encode('utf-8'))

    def test_valid_jwt_still_returns_200(self):
        auth = 'JWT ' + make_id_token(self.user.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content.decode(), 'a')
