"""
Authentication methods.

@var AUTHENTICATION_METHODS: dict mapping authentication method identifier to classes
@type AUTHENTICATION_METHODS: L{dict} of L{str} to cls
"""
import hashlib
import base64
import urllib.parse
import secrets
import time


try:
    import requests
except ImportError:
    requests = None

from bottle import HTTPError, redirect, abort


class BaseAuthenticationMethod(object):
    """
    Base class for authentication methods.

    @ivar auth_config: authentication configuration
    @type auth_config: L{pyzimtools.server.config.AuthConfig}
    """
    def __init__(self, auth_config):
        """
        The default constructor.

        @param auth_config: authentication configuration
        @type auth_config: L{pyzimtools.server.config.AuthConfig}
        """
        self.auth_config = auth_config

    def handle_auth(self, request, response):
        """
        Handle a request authentication.

        @param request: bottle request to authenticate
        @type request: L{bottle.BaseRequest}
        @param response: the bottle response
        @type response: L{bottle.BaseResponse}
        @return: if the authentication was successfull, a userid, L{None} otherwise
        @rtype: L{str} or L{None}
        """
        raise NotImplementedError("This needs to be overridden by a subclass!")

    def allow_user(self, userid):
        """
        Return True if the user is allowed access.

        @param userid: id of user (e.g. username)
        @type userid: L{str}
        @return: whether the user is allowed access
        @rtype: L{bool}
        """
        if self.auth_config.blacklist is not None:
            if userid in self.auth_config.blacklist:
                return False
        if self.auth_config.whitelist is not None:
            if userid not in self.auth_config.whitelist:
                return False
        return True

    def get_http_challenge(self):
        """
        Return the value to use for the challenge in the WWW-Authenticate header.

        @return: value for WWW-Authenticate header, if any should be used
        @rtype: L{str} or L{None}
        """
        return None

    def on_callback(self, request, response):
        """
        Called when something uses the /_pyzimserver/auth_callback ressource.

        @param request: bottle request making the request
        @type request: L{bottle.BaseRequest}
        @param response: the bottle response
        @type response: L{bottle.BaseResponse}
        """
        return HTTPError(404, "The authentication method of this site does not use the auth callback.")


class NoAuthentication(BaseAuthenticationMethod):
    """
    A pseudo authentication method that authorizes everything.
    """
    def handle_auth(self, request, response):
        return "no-userid"

    def allow_user(self, userid):
        return True


class BasePasswordAuthenticationMethod(BaseAuthenticationMethod):
    """
    Base class for username/password based authentication.

    Options:
        - 'message': message to send when the login was denied
        - 'realm': realm (message) to send as part of HTTP auth
    """
    def handle_auth(self, request, response):
        user, password = request.auth or (None, None)
        if (user is None) or (password is None):
            err = HTTPError(401, self.auth_config.options.get("message", "Accdess denied."))
            challenge = self.get_http_challenge()
            err.add_header("WWW-Authenticate", challenge)
            return err
        password_correct = self.check_password(userid=user, password=password)
        if not password_correct:
            return None
        elif self.allow_user(userid=user):
            return user
        else:
            return None

    def get_http_challenge(self):
        realm = self.auth_config.options.get("realm", "Login required!")  # TODO: encoding
        header = 'Basic realm="{realm}", charset="UTF-8"'.format(realm=realm)
        return header

    def check_password(self, userid, password):
        """
        Check a userid/password combination.

        @param userid: id of user (e.g. a username)
        @type userid: L{str}
        @param password: password provided by user
        @type password: L{str}
        @return: whether the authentication was successfull
        @rtype: L{bool}
        """
        raise NotImplementedError("This needs to be overridden by a subclass!")


class ConfigSinglePasswordAuthentication(BasePasswordAuthenticationMethod):
    """
    A simple authentication method using a single user/password combination specified in plaintext or hash in the config.

    Mostly used for testing.

    Options:
        - all used by L{BasePasswordAuthenticationMethod}
        - 'username': username used for login
        - 'password': password used for login (hexadecimal when using a hash algorithm)
        - 'password_type': name of an hash algorithm to apply to a password input, use 'plain' (default) to disable.
    """

    def check_password(self, userid, password):
        expected_user = self.auth_config.options.get("username", None)
        expected_password = self.auth_config.options.get("password", None)
        hash_alg = self.auth_config.options.get("password_type", "plain")
        if (expected_user is None) or (expected_password is None):
            # login not configured - let's paly it safe and deny the login
            return False
        if hash_alg == "plain":
            hashed_pswd = password
        else:
            hashed_pswd = hashlib.new(hash_alg, password).hexdigest()
        return (userid == expected_user and hashed_pswd == expected_password)


class OAuth2Authentication(BaseAuthenticationMethod):
    """
    An authentication method using oauth2. This enables integration with 3rd party tools

    Options:
        - authorize_url: URL used to start the authentication process
        - client_id: oauth client id, used to identify to the oauth service
        - client_secret: secret of the client, used to identify to the oauth service
        - scopes: a list of scopes to request and require, separated by spaces
        - pkce_type: PKCE/code challenge type to use, either "none", "S256" or "plain"
        - token_url: URL used to exchange the code for an access token
        - host: hostname of this server. Clients will get redirected to this host after signing in with the oauth provider. (optional)
        - host_https: seting this to "no" causes the generated redirect_url to use http (optional)
        - userid_url: if specified, a GET request will be done to this URL to get the current userid (optional)
        - userid_key: if specified, the response from 'userid_url' will be interpreted as json (instead of a userid) and this key will be used to extract the value (optional).
        - request_ttl: how long until a login attempt is considered expired. (default: 10 min)
        - cleanup_threshold: after how many ongoing requests should an internal cleanup be performed? (default: 1000)
    """
    def __init__(self, *args, **kwargs):
        BaseAuthenticationMethod.__init__(self, *args, **kwargs)
        self._oauth_sessions = {}  # state -> (expires, raw_challenge_code)

    def get_redirect_url(self, request):
        """
        Generate the URL to which the user should be redirected to by the oauth provider.

        @param request: bottle request making the request
        @type request: L{bottle.BaseRequest}
        @return: the url the user should be redirect to by the oauth provider
        @rtype: L{str}
        """
        site_name = self.auth_config.options.get("host", None)
        use_https = not (self.auth_config.options.get("host_https", "yes") in ("no", "false", "disable", "disabled", "0", "off"))
        if site_name is None:
            site_name = request.headers.get("Host", "default")
        if site_name is None:
            abort(400, "'Host' request header not set and no fixed host set in the config, unable to continue authentication.")
        redirect_url = "{}://{}/_pyzimserver/auth_callback".format(
            "https" if use_https else "http",
            site_name,
        )
        return redirect_url

    def handle_auth(self, request, response):
        state = secrets.token_hex(16)
        params = {
            "client_id": self.auth_config.options["client_id"],
            "redirect_uri": self.get_redirect_url(request),
            "scope": self.auth_config.options.get("scope", None),
            "state": state,
        }
        code_challenge = None
        challenge_type = self.auth_config.options.get("pkce_type", "S256")
        if challenge_type == "none":
            challenge_type = None
        elif challenge_type == "plain":
            raw_challenge = code_challenge = secrets.token_hex(43)
        elif challenge_type == "S256":
            raw_challenge = secrets.token_hex(43)
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(
                    raw_challenge.encode("utf-8")
                ).digest()
            ).replace(b"=", b"")
        else:
            return HTTPError(500, "Invalid challenge_type configured.")
        params["code_challenge_method"] = challenge_type
        params["code_challenge"] = code_challenge
        self._oauth_sessions[state] = (
            time.time() + int(self.auth_config.options.get("request_ttl", 6 * 10)),
            raw_challenge,
        )
        if len(self._oauth_sessions) >= int(self.auth_config.options.get("cleanup_threshold", 1000)):
            # clean up old oauth sessions
            to_del = []
            for k, v in self._oauth_sessions.items():
                if v[0] <= time.time():
                    to_del.append(k)
            for k in to_del:
                del self._oauth_sessions[k]
        filtered_params = {k: v for k, v in params.items() if v is not None}
        qs = urllib.parse.urlencode(filtered_params, doseq=False)
        final_url = "{}?{}".format(self.auth_config.options["authorize_url"], qs)
        return redirect(final_url)

    def on_callback(self, request, response):
        state = request.params.get("state", None)
        code = request.params.get("code", None)
        if (state is None) or (code is None):
            return HTTPError(422, "Missing oauth parameters 'state'and/or 'code'.")
        if state not in self._oauth_sessions:
            return HTTPError(422, "Unknown oauth2 session/invalid state-")
        expires, raw_code_challenge = self._oauth_sessions[state]
        del self._oauth_sessions[state]
        if time.time() >= expires:
            return HTTPError(422, "Oauth2 session expired, please try again.")
        params = {
            "client_id": self.auth_config.options["client_id"],
            "client_secret": self.auth_config.options["client_secret"],
            "code": code,
            "redirect_uri": self.get_redirect_url(request),
            "code_verifier": raw_code_challenge,
        }
        filtered_params = {k: v for k, v in params.items() if v is not None}
        r = requests.post(
            self.auth_config.options["token_url"],
            params=filtered_params,
            headers={
                "Accept": "application/json",
            },
        )
        if r.status_code != 200:
            return HTTPError(401, "OAuth2 login failed (non-200 response for token).")
        response = r.json()
        if "scope" in response:
            if not all([scope in response["scope"] for scope in self.auth_config.options.get("scope", "").split(" ")]):
                return HTTPError(401, "OAuth2 login failed (scope not granted).")
        token = response["access_token"]
        # get userid
        userid_url = self.auth_config.options.get("userid_url", None)
        userid_key = self.auth_config.options.get("userid_key", None)
        if userid_url is None:
            return token
        expects_json = (userid_key is not None)
        headers = {
            "Authorization": "Bearer " + token,
        }
        if expects_json:
            headers["Accept"] = "application/json"
        r = requests.get(
            userid_url,
            headers=headers,
        )
        if r.status_code != 200:
            return HTTPError(401, "OAuth2 login failed (non-200 response for userid).")
        if userid_key is None:
            return r.text
        else:
            return r.json()[userid_key]


class GitHubAuthentication(OAuth2Authentication):
    """
    A pre-configured version of L{OAuth2Authentication} for github.

    Options:
        - client_id: oauth client id, used to identify to the oauth service
        - client_secret: secret of the client, used to identify to the oauth service
        - host: hostname of this server. Clients will get redirected to this host after signing in with the oauth provider. (optional)
        - host_https: seting this to "no" causes the generated redirect_url to use http (optional)
        - request_ttl: how long until a login attempt is considered expired. (default: 10 min)
        - cleanup_threshold: after how many ongoing requests should an internal cleanup be performed? (default: 1000)
    """
    def __init__(self, *args, **kwargs):
        OAuth2Authentication.__init__(self, *args, **kwargs)
        self.auth_config.options["authorize_url"] = "https://github.com/login/oauth/authorize"
        self.auth_config.options["token_url"] = "https://github.com/login/oauth/access_token"
        self.auth_config.options["userid_url"] = "https://api.github.com/user"
        self.auth_config.options["userid_key"] = "login"
        self.auth_config.options["scopes"] = "user"
        self.auth_config.options["pkce_type"] = "S256"


AUTHENTICATION_METHODS = {
    "none": NoAuthentication,
    "single-config": ConfigSinglePasswordAuthentication,
    "oauth2": OAuth2Authentication,
    "github": GitHubAuthentication,
}
