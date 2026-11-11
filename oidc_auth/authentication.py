import logging
import time

import requests
from joserfc import jwt
from joserfc.errors import (BadSignatureError, ClaimError, DecodeError,
                            ExpiredTokenError, InvalidKeyIdError,
                            JoseError, UnsupportedAlgorithmError)
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry
from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.utils.encoding import smart_str
from django.utils.functional import cached_property
from django.utils.translation import gettext as _
from requests import request
from requests.exceptions import HTTPError
from rest_framework.authentication import (BaseAuthentication,
                                           get_authorization_header)
from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings
from .util import cache

logging.basicConfig()
logger = logging.getLogger(__name__)


def get_user_by_id(request, id_token):
    User = get_user_model()
    try:
        user = User.objects.get_by_natural_key(id_token.get('sub'))
    except User.DoesNotExist:
        msg = _('Invalid Authorization header. User not found.')
        raise AuthenticationFailed(msg)
    return user


class BaseOidcAuthentication(BaseAuthentication):
    @property
    @cache(ttl=api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)
    def oidc_config(self):
        return requests.get(
            api_settings.OIDC_ENDPOINT.rstrip('/') + '/.well-known/openid-configuration'
        ).json()


class BearerTokenAuthentication(BaseOidcAuthentication):
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        bearer_token = self.get_bearer_token(request)
        if bearer_token is None:
            return None

        try:
            userinfo = self.get_userinfo(bearer_token)
        except HTTPError:
            msg = _('Invalid Authorization header. Unable to verify bearer token')
            raise AuthenticationFailed(msg)

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, userinfo)

        return user, userinfo

    def get_bearer_token(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.BEARER_AUTH_HEADER_PREFIX.lower()
        if not auth or smart_str(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _(
                'Invalid Authorization header. Credentials string should not contain spaces.')
            raise AuthenticationFailed(msg)

        return auth[1]

    @cache(ttl=api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)
    def get_userinfo(self, token):
        userinfo_endpoint = self.oidc_config.get('userinfo_endpoint', api_settings.USERINFO_ENDPOINT)
        if not userinfo_endpoint:
            raise AuthenticationFailed(_('Invalid userinfo_endpoint URL. Did not find a URL from OpenID connect '
                                         'discovery metadata nor settings.OIDC_AUTH.USERINFO_ENDPOINT.'))

        response = requests.get(userinfo_endpoint, headers={
            'Authorization': 'Bearer {0}'.format(token.decode('ascii'))})
        response.raise_for_status()

        return response.json()


class JSONWebTokenAuthentication(BaseOidcAuthentication):
    """Token based authentication using the JSON Web Token standard"""

    www_authenticate_realm = 'api'
    www_authenticate_scheme = 'Bearer'

    # Correlates failure logs with the request; set per-request in
    # authenticate(), falls back to '-' when decode_jwt is called directly.
    trace_id = '-'

    @property
    def claims_options(self):
        _claims_options = {
            'iss': {
                'essential': True,
                'value': self.issuer
            }
        }
        for key, value in api_settings.OIDC_CLAIMS_OPTIONS.items():
            _claims_options[key] = value
        return _claims_options

    def authenticate(self, request):
        self.trace_id = request.META.get('HTTP_X_REQUEST_ID', '-')
        try:
            jwt_value = self.get_jwt_value(request)
            if jwt_value is None:
                return None
            payload = self.decode_jwt(jwt_value)
            self.validate_claims(payload)
        except AuthenticationFailed as exc:
            # Carry the RFC 6750 error info on the request so that
            # authenticate_header() (called by DRF on a fresh instance of
            # this class) can render it into the WWW-Authenticate header.
            request.oidc_auth_error = getattr(exc, 'oidc_error', 'invalid_token')
            request.oidc_auth_error_description = getattr(
                exc, 'oidc_error_description', None)
            raise

        # User resolution is deliberately outside the JWT error handling
        # above: permission and user-lookup errors must not be masked as
        # authentication failures.
        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, payload)

        return user, payload

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth or smart_str(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            raise self._authentication_failed(
                _('Invalid Authorization header. No credentials provided'),
                'no credentials in Authorization header', error='invalid_request')
        elif len(auth) > 2:
            raise self._authentication_failed(
                _('Invalid Authorization header. Credentials string should not contain spaces.'),
                'credentials string contains spaces', error='invalid_request')

        return auth[1]

    def jwks(self):
        return KeySet.import_key_set(self.jwks_data())

    @cache(ttl=api_settings.OIDC_JWKS_EXPIRATION_TIME)
    def jwks_data(self):
        return self.fetch_jwks_data()

    def fetch_jwks_data(self):
        r = request("GET", self.oidc_config['jwks_uri'], allow_redirects=True)
        r.raise_for_status()
        return r.json()

    def refresh_jwks_data(self):
        """Fetch a fresh JWKS from the IdP and update the cached key set.

        Triggered when a token references an unknown key id or fails
        signature verification, which usually means the IdP rotated its
        signing keys. A short-lived lock rate-limits these fetches so a
        flood of invalid tokens cannot hammer the IdP (cache penetration).
        """
        django_cache = caches[api_settings.OIDC_CACHE_NAME]
        lock_key = api_settings.OIDC_CACHE_PREFIX + 'jwks_refresh_lock'
        if not django_cache.add(
                lock_key, True, timeout=api_settings.OIDC_JWKS_REFRESH_LOCK_TIMEOUT):
            # A refresh happened very recently; use whatever is cached now.
            return self.jwks_data()
        try:
            jwks_data = self.fetch_jwks_data()
        except Exception:
            logger.warning('Unable to refresh JWKS [trace_id=%s]',
                           self.trace_id, exc_info=True)
            return self.jwks_data()
        django_cache.set(
            self.jwks_data.make_key(), jwks_data,
            timeout=api_settings.OIDC_JWKS_EXPIRATION_TIME,
            version=self.jwks_data.cache_version)
        return jwks_data

    @cached_property
    def issuer(self):
        return self.oidc_config['issuer']

    def decode_jwt(self, jwt_value):
        try:
            key_set = self.jwks()
        except ValueError as e:
            raise self._authentication_failed(
                _('Invalid Authorization header. JWT signature key not found.'),
                'cached JWKS could not be imported', e)

        try:
            return self._decode_token(jwt_value, key_set)
        except (InvalidKeyIdError, BadSignatureError):
            # Unknown key id or signature mismatch: the IdP may have rotated
            # its signing keys since the JWKS was cached. Refresh the key set
            # (rate-limited) and retry once before rejecting the token.
            try:
                key_set = KeySet.import_key_set(self.refresh_jwks_data())
            except ValueError as e:
                raise self._authentication_failed(
                    _('Invalid Authorization header. JWT signature key not found.'),
                    'refreshed JWKS could not be imported', e)
            try:
                return self._decode_token(jwt_value, key_set)
            except (InvalidKeyIdError, BadSignatureError) as e:
                raise self._authentication_failed(
                    _('Invalid Authorization header. JWT Signature verification failed.'),
                    'signature verification failed', e)

    def _decode_token(self, jwt_value, key_set):
        """Decode and verify a JWT against the given key set.

        Only JWT parsing and signature verification errors are converted to
        401s here; InvalidKeyIdError and BadSignatureError are re-raised so
        decode_jwt() can retry once with a refreshed key set.
        """
        try:
            token = jwt.decode(
                jwt_value.decode('ascii'),
                lambda header: key_set,
                algorithms=api_settings.JWT_ALGORITHMS
            )
        except (InvalidKeyIdError, BadSignatureError):
            raise
        except UnsupportedAlgorithmError as e:
            raise self._authentication_failed(
                _('Invalid Authorization header. JWT algorithm not allowed.'),
                'JWT algorithm not allowed', e)
        except (DecodeError, ValueError) as e:
            # DecodeError: malformed JWT. ValueError (incl.
            # UnicodeDecodeError): non-ASCII or otherwise undecodable input.
            raise self._authentication_failed(
                _('Invalid Authorization header. JWT could not be decoded.'),
                'undecodable JWT', e)
        except JoseError as e:
            raise self._authentication_failed(
                _('Invalid Authorization header. JWT could not be verified.'),
                'JWT verification failed', e)

        return token.claims

    def validate_claims(self, id_token):
        registry = JWTClaimsRegistry(
            now=int(time.time()),
            leeway=api_settings.OIDC_LEEWAY,
            **self.claims_options
        )
        try:
            registry.validate(id_token)
        except ExpiredTokenError as e:
            raise self._authentication_failed(
                _('Invalid Authorization header. JWT has expired.'),
                'JWT has expired', e)
        except ClaimError as e:
            # The specific claim error goes to the log only; claim names and
            # values are internal details that must not leak into responses.
            raise self._authentication_failed(
                _('Invalid Authorization header. JWT claims validation failed.'),
                'JWT claims validation failed: {0}'.format(e), e)
        except JoseError as e:
            raise self._authentication_failed(
                _('Invalid Authorization header. JWT could not be validated.'),
                'JWT validation failed: {0}'.format(e), e)

        if id_token.get('iat', 0) < int(time.time()) - api_settings.OIDC_LEEWAY:
            raise self._authentication_failed(
                _('Invalid Authorization header. JWT too old.'),
                'JWT issued too long ago')

    def _authentication_failed(self, message, reason, exc=None, error='invalid_token'):
        """Log the real failure reason and build a 401 with a safe message.

        The log line carries the specific reason and the request's trace id;
        the public message stays generic so no claims, key material or other
        internals end up in the response body.
        """
        if exc is None:
            logger.warning('JWT authentication failed [trace_id=%s]: %s',
                           self.trace_id, reason)
        else:
            logger.exception('JWT authentication failed [trace_id=%s]: %s',
                             self.trace_id, reason)
        failure = AuthenticationFailed(message)
        failure.oidc_error = error
        failure.oidc_error_description = message
        return failure

    def authenticate_header(self, request):
        """Render an RFC 6750 compliant WWW-Authenticate header."""
        header = '{0} realm="{1}"'.format(
            self.www_authenticate_scheme, self.www_authenticate_realm)
        error = getattr(request, 'oidc_auth_error', None)
        if error:
            header += ', error="{0}"'.format(error)
            description = getattr(request, 'oidc_auth_error_description', None)
            if description:
                header += ', error_description="{0}"'.format(description)
        return header
