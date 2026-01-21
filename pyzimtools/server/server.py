"""
The central server class.

@var STATIC_PATH: path to the static file directory
@type STATIC_PATH: L{str}
"""
import os
import glob
import time
import json
from collections import namedtuple
from urllib.parse import urljoin

import bottle
from bottle import request, response, parse_range_header, HTTPResponse, HTTPError
from jinja2 import Environment, PackageLoader
from pyzim import Zim
from pyzim.exceptions import EntryNotFound

from .exceptions import ZimNotFound
from .config import Config
from .auth import AUTHENTICATION_METHODS


assert __file__
STATIC_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "static",
)

ZimMeta = namedtuple(
    "ZimMeta",
    (
        "title",
        "path",
        "description",
        "language",
        "date",
    ),
)


class Webserver(object):
    """
    The Webserver is the central class of the server.

    It manages all components and provides the webserver.

    @ivar app: the bottle application
    @type app: L{bottle.Bottle}
    @ivar config: configuration for the server
    @type config: L{pyzimtools.server.config.Config}
    @ivar zim_cache: cache for ZIM files (abs path -> Zim object)
    @type zim_cache: L{pyzim.cache.BaseCache}
    @ivar zim_metas: a dictionary mapping ZIM paths to tuples of (mtime, meta) or L{None}
    @type zim_metas: L{None} or L{dict} of L{str} -> L{ZimMeta}
    @ivar zim_illustrations: a dictionary mapping ZIM paths to illustration data or L{None}
    @type zim_illustrations: L{None} or L{dict} of L{str} -> L{bytes}
    @ivar auth_instances: used to keep track of auth instances, maps site name -> auth to use
    @type auth_instances: L{dict} of L{str} to L{pyzimtools.server.auth.BaseAuthenticationMethod}
    @ivar environment: the jinja2 environment used to render web pages
    @type environment: L{jinja2.Environment}
    """
    def __init__(self, config):
        """
        The default constructor.

        @param config: configuration for the server
        @type config: L{pyzimtools.server.config.Config}
        """
        assert isinstance(config, Config)
        self.config = config

        self.zim_cache = self.config.get_zim_cache()
        if self.config.cache_zim_metadata:
            self.zim_metas = {}
        else:
            self.zim_metas = None
        if self.config.cache_zim_illustrations:
            self.zim_illustrations = {}
        else:
            self.zim_illustrations = None
        self.auth_instances = {}

        self.environment = Environment(
            loader=PackageLoader(
                "pyzimtools",
                package_path=os.path.join("server", "templates"),
            ),
            autoescape=True,
        )

        self.app = bottle.Bottle()
        self.app.get("/_pyzimserver/<path:path>", callback=self.on_get_special)
        self.app.get("<path:path>", callback=self.on_get_path)

    def run(self):
        """
        Run the webserver.
        """
        self.app.run(
            host=self.config.interface,
            port=self.config.port,
            server=self.config.server,
            **self.config.server_options,
        )

    def on_get_path(self, path):
        """
        Called when a GET request was received.

        @param path: path that was requested
        @type path: L{str}
        @return: response content as understood by bottle
        """
        # get the requested host
        site_config = self.get_site_config(request)
        site_mode = site_config.mode

        # authentication
        if site_config.auth is not None:
            auth = self.get_auth_for_site(site_config)
            challenge = auth.get_http_challenge()
            user_cookie = request.get_cookie("account", secret=site_config.cookie_secret)
            userid = None
            if user_cookie:
                user_cookie = json.loads(user_cookie)
                if user_cookie["expires"] <= time.time():
                    response.set_cookie("account", "")
                else:
                    userid = user_cookie["userid"]
            if userid is None:
                userid = auth.handle_auth(request, response)
                # NOTE: login code is mirrored in auth callback
                if isinstance(userid, bottle.HTTPError):
                    return userid
            if (userid is None) or (not auth.allow_user(userid)):
                # re-transmit a challenge to allow another login
                err = HTTPError(401, "Authentication failed.")
                if challenge is not None:
                    err.add_header("WWW-Authenticate", challenge)
                return err
            # set login cookie
            self.set_user_logged_in(response, site_config, userid)

        # parse request path
        if site_mode == "multi":
            if path == "/":
                # request for the main page
                return self.on_get_mainpage(site_config=site_config)
            elif path.lower() == "/favicon.ico":
                # request for favicon
                return self.on_get_favicon(site_config=site_config)
            else:
                # serve a page for a ZIM
                _, file_name, zimpath = path.split("/", 2)
        elif site_mode == "single":
            if path == "/":
                # redirect to ZIM page
                zim_name = os.path.basename(site_config.path)
                return bottle.redirect("/{}/".format(zim_name))
            elif path.lower() == "/favicon.ico":
                # request for favicon
                return self.on_get_favicon(site_config=site_config)
            else:
                _, file_name, zimpath = path.split("/", 2)
        elif site_mode == "direct":
            file_name = None
            _, zimpath = path.split("/", 1)
        else:
            raise RuntimeError("Unreachable point reached (site mode unknown)!")

        # get ZIM
        try:
            zim = self.get_zim_for(site_config=site_config, name=file_name)
        except ZimNotFound:
            return bottle.abort(code=404, text="The specified ZIM file could not be found!")

        # respond
        return self.serve_entry(
            zim=zim,
            path=zimpath,
            base_path=file_name,
            site_config=site_config,
        )

    def on_get_mainpage(self, site_config):
        """
        Called when the main page should be served.

        @param site_config: configuration for the site being accessed
        @type site_config: L{pyzimtools.server.config.SiteConfig}
        @return: response content as understood by bottle
        """
        # handle auth
        if site_config.auth is not None:
            auth = self.get_auth_for_site(site_config)
            success = auth.handle_auth(request, response)
            if isinstance(success, bottle.HTTPError):
                return success
            elif not success:
                return bottle.abort(code=401, text="Authentication failed!")
        # list zim files
        if (site_config.path is None) or (not os.path.exists(site_config.path)):
            # path to ZIM file directory does not exists
            return bottle.abort(code=404, text="ZIM directory does not exist!")
        available_zims = self.list_zim_files(site_config)

        # response
        template = self.environment.get_template("zimlistpage.html.jinja")
        html = template.render(to_root="", zims=available_zims)
        return html

    def on_get_favicon(self, site_config):
        """
        Called when the favicon should be served.

        @param site_config: configuration for the site being accessed
        @type site_config: L{pyzimtools.server.config.SiteConfig}
        @return: response content as understood by bottle
        """
        return bottle.abort(404)  # TODO

    def on_get_special(self, path):
        """
        Serve a request to the "special" path.

        @param path: name of the ressource requested
        @type path: L{str}
        """
        site_config = self.get_site_config(request)

        if path.startswith("illustration/"):
            zim_name = path.replace("illustration/", "", 1)
            if (self.zim_illustrations is not None) and (zim_name in self.zim_illustrations):
                data = self.zim_illustrations[zim_name]
            else:
                zim = self.get_zim_for(site_config, name=zim_name)
                data = zim.get_metadata("Illustration_48x48@1", as_unicode=False)
                if data is None:
                    # no illustration
                    return bottle.abort(404)
                if self.zim_illustrations is not None:
                    self.zim_illustrations[zim_name] = data
            response.set_header("Content-Type", "image/png")
            return data
        elif path == "style.css":
            return bottle.static_file("style.css", root=STATIC_PATH)
        elif path == "auth_callback":
            auth = self.get_auth_for_site(site_config)
            userid = auth.on_callback(request, response)
            # NOTE: login code is mirrored in login
            if isinstance(userid, bottle.HTTPError):
                return userid
            elif userid is None:
                return bottle.abort(code=401, text="Authentication failed!")
            elif not auth.allow_user(userid):
                return bottle.abort(code=401, text="Authentication failed!")
            # set login cookie
            self.set_user_logged_in(response, site_config, userid)
        else:
            # unknown ressource
            return bottle.abort(404)

    def get_site_config(self, request):
        """
        Return the site configuration to use for the request.

        @param request: the bottle request
        @type request: L{bottle.BaseRequest}
        @return: the site config for the requested site
        @rtype: L{pyzimtools.server.config.SiteConfig}
        """
        site_name = request.headers.get("Host", "default")
        if self.config.strip_ports and (":" in site_name):
            site_name = site_name[:site_name.rfind(":")]
        site_config = self.config.get_site_config(site_name)
        return site_config

    def list_zim_files(self, site_config):
        """
        List the zim files available on a site in multi-mode.

        @param site_config: configuration for the site for which to list files
        @type site_config: L{pyzimtools.server.config.SiteConfig}
        @return: a list of zim files
        @rtype: L{list} of L{ZimMeta}
        """
        file_names = glob.glob(
            site_config.filter,
            root_dir=site_config.path,
            recursive=False,
            include_hidden=False,  # play it save
        )
        zim_metas = [self.get_zim_meta_for_path(site_config, fn) for fn in file_names]
        return zim_metas

    def get_zim_meta_for_path(self, site_config, path):
        """
        Return the zim meta for a specific path

        @param site_config: configuration for the site for which to get metadata for
        @type site_config: L{pyzimtools.server.config.SiteConfig}
        @param path: path to zim to get metadata for
        @type path: L{str}
        @return: the zim metadata
        @rtype: L{ZimMeta}
        """
        if (self.zim_metas is not None) and (path in self.zim_metas):
            return self.zim_metas[path]
        bp = os.path.basename(path)
        zim = self.get_zim_for(site_config, bp)
        meta = ZimMeta(
            path=bp,
            title=(zim.get_metadata("Title") or os.path.basename(path)),
            description=(zim.get_metadata("Description") or ""),
            language=(zim.get_metadata("Language") or "eng"),
            date=(zim.get_metadata("Date") or "????-??-??"),
        )
        if self.zim_metas is not None:
            self.zim_metas[path] = meta
        return meta

    def get_zim_for(self, site_config, name=None):
        """
        Return the ZIM for the specified site.

        @param site_config: configuration for the site being accessed
        @type site_config: L{pyzimtools.server.config.SiteConfig}
        @param name: if site is in multi mode, select the ZIM to use
        @type name: L{str}
        @return: ZIM object for the site
        @rtype: L{pyzim.archive.Zim}
        """
        mode = site_config.mode
        if mode == "single":
            expected_name = os.path.basename(site_config.path)
            if name != expected_name:
                # wrong file part in request path
                raise ZimNotFound("No content for ZIM '{}' available.".format(name))
            path = os.path.abspath(site_config.path)
        elif mode == "direct":
            path = os.path.abspath(site_config.path)
        elif mode == "multi":
            if ("/" in name) or (".." in name):
                # do not allow requests to a ZIM containing either of these symbols
                raise ZimNotFound("Forbidden symbol in path!")
            path = os.path.abspath(os.path.join(site_config.path, name))
            if not (os.path.exists(path) and os.path.isfile(path)):
                raise ZimNotFound("No such ZIM :'{}'!".format(path))
        else:
            raise RuntimeError("Unreachable state reached (zim mode check)!")

        if self.zim_cache.has(path):
            zim = self.zim_cache.get(path)
        else:
            policy = site_config.get_policy()
            zim = Zim.open(path=path, mode="r", policy=policy)
            self.zim_cache.push(path, zim)
        return zim

    def get_auth_for_site(self, site_config):
        """
        Return the authentication method to use for a site.

        Instances are cached.

        @param site_config: config for the site to get auth for
        @type site_config: L{pyzimtools.server.config.SiteConfig}
        @return: the instance of the authentication mechansism
        @rtype: L{pyzimtools.server.auth.BaseAuthenticationMethod} or L{None}
        """
        name = site_config.name
        if name not in self.auth_instances:
            auth_config = site_config.get_auth_config()
            cls = AUTHENTICATION_METHODS[auth_config.type]
            ins = cls(auth_config)
            self.auth_instances[name] = ins
        return self.auth_instances[name]

    def set_user_logged_in(self, response, site_config, userid):
        """
        Set the user as logged in.

        @param site_config: config for the site in which the user should be logged in
        @type site_config: L{pyzimtools.server.config.SiteConfig}
        @param response: the bottle response
        @type response: L{bottle.BaseResponse}
        @param userid: userid specifying the identity of the user
        @type userid: L{str}
        """
        expires = time.time() + site_config.get_auth_config().login_ttl
        response.set_cookie(
            "account",
            json.dumps(
                {
                    "userid": userid,
                    "expires": expires,
                }
            ),
            path="/",
            expires=expires,
            secret=site_config.cookie_secret,
        )

    def serve_entry(self, zim, path, base_path, site_config):
        """
        Serve an entry from the ZIM file.

        @param zim: zim to get entry from
        @type zim: L{pyzim.archive.Zim}
        @param path: path of entry to serve
        @type path: L{str}
        @param base_path: base path to the ZIM root, used for redirects
        @type base_path: L{str}
        @param site_config: config for the site
        @type site_config: L{pyzimtools.server.config.SiteConfig}
        """
        if path == "":
            # main page - redirect to mainpage entry
            entry = zim.get_mainpage_entry().resolve()
            target_path = entry.url
            return bottle.redirect(target_path)
        try:
            entry = zim.get_content_entry_by_url(path)
        except EntryNotFound:
            # no such entry, respond with 404
            bottle.abort(404, "ZIM file does not contain an entry for path '{}'!".format(path))
        else:
            # an entry exists, it may be a redirect though
            if entry.is_redirect:
                # redirect the client
                # we need to know the next entry in order to get the URL#
                # thus, we follow thee entry once
                target_entry = entry.follow()
                target_url = target_entry.url
                # adjust redirect for ZIM serving type
                if site_config.mode == "direct":
                    # all redirects should be absolute
                    target_url = urljoin("/", target_url)
                else:
                    # all redirects should be absolute and start with the ZIM name
                    if target_url.startswith("/"):
                        target_url = target_url[1:]
                    if not base_path.endswith("/"):
                        base_path += "/"
                    target_url = urljoin(urljoin("/", base_path), target_url)
                print("Redirecting: ", path, " -> ", target_url)
                bottle.redirect(target_url)
            else:
                # content entry
                # support for content ranges
                is_head = (bottle.request.method == "HEAD")
                headers = {}
                headers["Accept-Ranges"] = "bytes"
                range_header = bottle.request.environ.get("HTTP_RANGE")
                csize = entry.get_size()
                if range_header:
                    ranges = list(parse_range_header(range_header, csize))
                    if not ranges:
                        return bottle.abort(416, "Requested Range Not Satisfiable")
                    offset, end = ranges[0]
                    rlen = end - offset
                    headers["Content-Range"] = "bytes {}-{}/{}".format(offset, end - 1, csize)
                    headers["Content-Length"] = str(rlen)
                    headers["Content-Type"] = entry.mimetype
                    if is_head:
                        body = ""
                    else:
                        body = entry.iter_read(buffersize=2**15, start=offset, end=end)
                    return HTTPResponse(body, status=206, **headers)
                # serve the content directly
                # we use .iter_read(), as bottle allows returning generators
                # this allows us to serve larger files more RAM friendly
                # set mimetype
                bottle.response.content_type = entry.mimetype
                bottle.response.set_header("Accept-Ranges", "bytes")
                return entry.iter_read(buffersize=2**15)
