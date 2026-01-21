"""
Configuration handling.

@var EXAMPLE_CONFIG: the example configuration that will be written when `--write-config` is specified. Also serves as documentation.
@type EXAMPLE_CONFIG: L{str}
"""
import configparser
import os
import secrets

from pyzim.cluster import Cluster, OffsetRememberingCluster, InMemoryCluster
from pyzim.pointerlist import SimplePointerList, OnDiskSimplePointerList, OrderedPointerList, OnDiskOrderedPointerList, TitlePointerList, OnDiskTitlePointerList
from pyzim.cache import TopAccessCache, LastAccessCache, HybridCache, NoOpCache
from pyzim.policy import Policy


EXAMPLE_CONFIG = """
[general]
# general configuration
# this section contains settings for the webserver itself as well as
# some settings about caching

# which interface to listen on
interface=0.0.0.0
# which port to listen on
port=8080

# pyzim-server uses the bottle microframework, which in turn can use one
# of several WSGI servers, which have their own up- and downsides
# for example, you may need to change this to support TLS
# which WSGI server to use
# see the bottle documentation for possible values
server=wsgiref
# you can specify extra server options like this:
# server_option int myIntOption=3
# server_option boolean some_bool_option=yes
# server_option string plain_option="foo"

# whether the port should be ignored when looking up sites in the config
strip_ports=false

# which cache to use for opened ZIM files. Possible values:
#  - last: cache the most recently accessed zims
#  - top: cache the most commonly accessed ZIMs
#  - hybrid: cache both
#  - none: disable caching
zim_cache_type=last
# how many of the most recently accessed ZIMs should be cached
# this is for both last and hybrid caches
last_zim_cache_size=3
# how many of the most commonly accessed ZIMs should be cached
# this is for both top and hybrid caches
top_zim_cache_size=3

# showing the list of zimfiles in multi-mode requires some extra
# informations. Reading them each time has negative performance impact and
# may mess up caching. Consequently, these are usually cached. You can
# disable the caching behavior here.
# whether zim metadata should be cached
cache_zim_metadata=true
# whether zim metadata illustrations (not images in the ZIM) should be cached
cache_zim_metadata=true

[auth default]
# default authentication configuration
# all sites default to this one
# all other auth configs inherit from here (unless otherwise specified)

# all authentication methods support the following options:
# parent auth config to inherit from
parent=default
# authentication method to use (default: none)
type=none

# only allow users whose name is in this list (alias: allowlist)
whitelist=myName,myOtherName
# prevent users whose name is in this list (alias: blocklist)
blacklist=myThirdName
# how long are users kept logged in in seconds? (default: 2 hours)
login_ttl=7200

[auth my_auth]
# example authentication method to use a fixed username password
# here, we use username "user" and password "password"
# from which auth section to inherit some values (default: default)
parent=default
# specify that we want to use a fixed password from the config
type=single-config
# message to send when the login was denied
option message=Login denied.
# message to send to request login
option realm=Please login.
# username for login
option username=user
# whether the password is stored hashed
option password_type=sha256
# the (hashed, if enabled) password to expect
option password=5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# in this example config, we've inherited the values for "whitelist" and "blacklist"
# we need to include "user" in the whitelist
whitelist=user


[auth oauth2exampleauth]
# an example configuration for oauth2
# we are using github as an example here
# NOTE: if you need to specify a redirect/callback URL for your oauth2
#       provider, use "https://[hostname]/_pyzimserver/auth_callback"

# specify this is an oauth2 (webflow) authentication
type=oauth2
# URL to redirect the user to in order to start the authorization process
option authorize_url=https://github.com/login/oauth/authorize
# client id and secret to use
option client_id=...
option client_secret=...
# scopes to require, seperated by space (github requires 'user' scope to get user info)
option scopes=user
# PKCE challenge to use. Either "none", "S256" or "plain". GitHub requires "S256"
option pkce_type=S256
# the URL where we can access the code for an access token.
option token_url=https://github.com/login/oauth/access_token
# the host to use to redirect back to the site (aka callback URL). (optional, default: use client "Host" header)
# option host=
# if the redirect/callback URL should use https (default: yes, obviously)
option host_https=yes
# if you want to use the whitelist/blacklist feature, we need a way to get the username
# if set (optionally), a GET request will be made to the userid_url with the previously acquired bearer token to get the username
option userid_url=https://api.github.com/user
# by default, the userid_url is assumed to return the username. sometimes, however, you may get a json response
# if userid_key is set, the response will be interpreted as json and only the value corresponding to the userid_key will be used
option userid_key=login
# we need to keep track of ongoing authorization attempts, which requires RAM
# the request_ttl option (default: 10min) specifies how long we want to keep the data arround
option request_ttl=600
# to improve performance, we only clean up the list of such requests when more than cleanup_threshold requests are stored in memory (default: 1000)
option cleanup_threshold=1000

[auth ghauth]
# the above example used github. There's a preconfigured auth mechanism for this, to keep things simple.
# NOTE: if you need to specify a redirect/callback URL for your oauth2
#       provider, use "https://[hostname]/_pyzimserver/auth_callback"
type=github
# client id and secret are required
option client_id=...
option client_secret=...
# the host to use to redirect back to the site (aka callback URL). (optional, default: use client "Host" header)
# option host=
# if the redirect/callback URL should use https (default: yes, obviously)
option host_https=yes
# we need to keep track of ongoing authorization attempts, which requires RAM
# the request_ttl option (default: 10min) specifies how long we want to keep the data arround
option request_ttl=600
# to improve performance, we only clean up the list of such requests when more than cleanup_threshold requests are stored in memory (default: 1000)
option cleanup_threshold=1000

[site default]
# default site configuration
# all other site configs inherit from here (unless otherwise specified)

[site example.org]
# an example site
# parent to copy default values from
# defaults to "default", but can also be "none" or a site name.
parent=default
# the mode to operate under:
#  - multi: serve all ZIMs available
#  - single: serve only a single ZIM, redirecting from / to the ZIM
#  - direct: serve the content of a single ZIM, acting like the ZIM root is also the site root.
mode=multi
# the path of the ZIM file(s). In single/direct mode, this should be a ZIM file, in multi mode a directory
path=.
# in multi-mode, a unix-like filter to filter file names in the directory
filter=*.zim
# which authentication mechanism to use
auth=my_auth
# secret to use for signing cookies (default: random value)
cookie_secret=

# policy options - these options allow you to fine controll ressource allocation
# what kind of cluster to use (possible values: 'offset_remembering', 'in_memory', 'no_cache'
cluster_type=offset_remembering
# which cache to use for entry metadata (not content). See general.zim_cache_type for more info.
entry_cache_type=hybrid
# how many of the most recently accessed entries should be cached
last_entry_cache_size=50
# how many of the most commonly accessed entries should be cached
top_entry_cache_size=100
# which cache to use for clusters (entry content). See general.zim_cache_type for more info.
cluster_cache_type=last
# how many of the most recently accessed clusters should be cached
last_cluster_cache_size=2
# how many of the most commonly accessed clusters should be cached
top_cluster_cache_size=2
# what kind of pointer list to use (values: 'on_disk', 'in_memory')
simple_pointer_list_type=in_memory
ordered_pointer_list_type=in_memory
title_pointer_list_type=in_memory
"""


def _get_cache(cache_type, last_size, top_size):
    """
    Instantiate a new cache for the specified configuration.

    @param cache_type: type of cache to instantiate (hybrid, top, last)
    @type cache_type: L{str}
    @param last_size: how many of the most recently accessed elements to cache
    @type last_size: L{int}
    @param top_size: how many of the most commonly accessed elements to cache
    @type top_size: L{int}
    @return: a new cache with the specified parameters
    @rtype: L{pyzim.cache.BaseCache}
    @raises KeyError: if the cache_type is invalid
    """
    cls, kwargs = _get_cache_config(cache_type, last_size=last_size, top_size=top_size)
    cache = cls(**kwargs)
    return cache


def _get_cache_config(cache_type, last_size, top_size):
    """
    Return the cache class and parameters to use.

    @param cache_type: type of cache to get config for (hybrid, top, last)
    @type cache_type: L{str}
    @param last_size: how many of the most recently accessed elements to cache
    @type last_size: L{int}
    @param top_size: how many of the most commonly accessed elements to cache
    @type top_size: L{int}
    @return: a tuple specifying the class to use and the keyword arguments
    @rtype: L{tuple} of (subclass of L{pyzim.cache.BaseCache}, L{dict})
    @raises KeyError: if the cache_type is invalid
    """
    assert isinstance(cache_type, str)
    assert isinstance(last_size, int) and last_size > 0
    assert isinstance(top_size, int) and top_size > 0
    if cache_type == "last":
        cls = LastAccessCache
        kwargs = {"max_size": last_size}
    elif cache_type == "top":
        cls = TopAccessCache
        kwargs = {"max_size": last_size}
    elif cache_type == "hybrid":
        cls = HybridCache
        kwargs = {"last_cache_size": last_size, "top_cache_size": top_size}
    elif cache_type == "none":
        cls = NoOpCache
        kwargs = {}
    else:
        raise KeyError("Invalid cache type: {}".format(cache_type))
    return (cls, kwargs)


class ConfigurationError(Exception):
    """
    Exception raised when the configuration is invalid
    """
    pass


class SiteConfig(object):
    """
    A configuration for a specific site.

    @ivar parent: the configuration this site config is part of
    @type parent: L{Config}
    @ivar name: name of the site this config is for
    @type name: L{str}
    @ivar mode: mode the site is in (e.g. "multi", "single", "direct")
    @type mode: L{str}
    @ivar path: path to the file or directory to serve
    @type path: L{str}
    @ivar filter: unix-like filter (e.g. *.zim) to filter for files in the directory
    @type filter: L{str}
    @ivar auth: name of authentication mechanism to use
    @type auth: L{str}
    @ivar cookie_secret: secret to use for cookies
    @type cookie_secret: L{str}

    @ivar entry_cache_type: type of cache to use for entries
    @type entry_cache_type: L{str}
    @ivar last_entry_cache_size: how many of the most recently accessed entries to cache
    @type last_entry_cache_size: L{int}
    @ivar top_entry_cache_size: how many of the most commnonly accessed entries to cache
    @type top_entry_cache_size: L{int}
    @ivar cluster_cache_type: type of cache to use for clusters
    @type cluster_cache_type: L{str}
    @ivar last_cluster_cache_size: how many of the most recently accessed clusters to cache
    @type last_cluster_cache_size: L{int}
    @ivar top_cluster_cache_size: how many of the most commnonly accessed clusters to cache
    @type top_cluster_cache_size: L{int}
    """
    def __init__(self, parent, name):
        """
        The default constructor.

        @param parent: the configuration this site config is part of
        @type parent: L{Config}
        @param name: name of the site this config is for
        @type name: L{str}
        """
        assert isinstance(parent, Config)
        assert isinstance(name, str)
        self.parent = parent
        self.name = name

        self.mode = "multi"
        self.path = "."
        self.filter = "*.zim"
        self.auth = "default"
        self.cookie_secret = secrets.token_hex(16)

        self.cluster_type = "offset_remembering"
        self.simple_pointer_list_type = "in_memory"
        self.ordered_pointer_list_type = "in_memory"
        self.title_pointer_list_type = "in_memory"
        self.entry_cache_type = "hybrid"
        self.last_entry_cache_size = 50
        self.top_entry_cache_size = 100
        self.cluster_cache_type = "last"
        self.last_cluster_cache_size = 2
        self.top_cluster_cache_size = 2

    def copy_from(self, other):
        """
        Copy configuration values from the specified site configuration.

        @param other: site configuration to copy from
        @type other: L{SiteConfig}
        """
        assert isinstance(other, self.__class__)
        to_copy = (
            "mode", "path", "entry_cache_type", "last_entry_cache_size",
            "top_entry_cache_size", "cluster_cache_type", "last_cluster_cache_size",
            "top_cluster_cache_size", "filter", "auth", "cookie_secret",
            "cluster_type", "simple_pointer_list_type", "ordered_pointer_list_type",
            "title_pointer_list_type",
        )
        for key in to_copy:
            setattr(self, key, getattr(other, key))

    def parse(self, config, section):
        """
        Parse a site section in the configuration.

        @param config: config to parse
        @type config: L{configparser.ConfigParser}
        @param section: name of section to parse
        @type section: L{str}
        """
        # handle inheritance
        parent_name = config.get(section, "parent", fallback="default")
        if parent_name != "none":
            if parent_name not in self.parent.site_configs:
                raise ConfigurationError("Unknown site parent: {}!".format(parent_name))
            parent = self.parent.site_configs[parent_name]
            self.copy_from(parent)

        if config.has_option(section, "mode"):
            self.mode = config.get(section, "mode")
            if self.mode not in ("single", "multi", "direct"):
                raise ConfigurationError("Unknown site mode: {}!".format(self.mode))
        if config.has_option(section, "path"):
            self.path = config.get(section, "path")
            if not os.path.exists(self.path):
                raise ConfigurationError("Path {} does not exists!".format(self.path))
            if self.mode in ("single", "direct"):
                if not os.path.isfile(self.path):
                    raise ConfigurationError("Path {} does not point to a single file as required by mode!".format(self.path))
            else:
                if not os.path.isdir(self.path):
                    raise ConfigurationError("Path {} does not point to a directory as required by mode!".format(self.path))
        if config.has_option(section, "filter"):
            self.filter = config.get(section, "filter")
        if config.has_option(section, "auth"):
            self.auth = config.get(section, "auth")
            if self.auth not in self.parent.auth_configs:
                raise ConfigurationError("Unknown auth config (yo may have to change the definition order in the config): {}!".format(self.auth))
        if config.has_option(section, "cookie_secret"):
            self.cookie_secret = config.get(section, "cookie_secret")
            if not self.cookie_secret:
                raise ConfigurationError("'secret_cookie' in section '{}' is specified but left empty, raising an exception to avoid a securtiy concern!".format(section))
        for key in ("entry_cache_type", "cluster_cache_type"):
            if config.has_option(section, key):
                value = config.get(section, key)
                if value not in ("last", "top", "hybrid", "none"):
                    raise ConfigurationError("Invalid cache type: {}!".format(value))
                setattr(self, key, value)
        for key in ("last_entry_cache_size", "top_entry_cache_size", "last_cluster_cache_size", "top_cluster_cache_size"):
            if config.has_option(section, key):
                value = config.getint(section, key)
                setattr(self, key, value)
        if config.has_option(section, "cluster_type"):
            v = config.get(section, "cluster_type")
            if v not in ("in_memory", "no_cache", "offset_remembering"):
                raise ConfigurationError("Unknown value for cluster_type: {}".format(v))
            self.cluster_type = v
        for key in ("simple_pointer_list_type", "ordered_pointer_list_type", "title_pointer_list_type"):
            if config.has_option(section, key):
                v = config.get(section, key)
                if v not in ("in_memory", "on_disk"):
                    raise ConfigurationError("Unknown value for {}: {}".format(key, v))
                setattr(self, key, v)

    def get_policy(self):
        """
        Generate a policy to use for ZIMs for this site.

        @return: a policy that should be used to open ZIMs for this site
        @rtype: L{str}
        """
        cluster_types = {
            "no_cache": Cluster,
            "offset_remembering": OffsetRememberingCluster,
            "in_memory": InMemoryCluster,
        }
        list_types = {
            "on_disk": (OnDiskSimplePointerList, OnDiskOrderedPointerList, OnDiskTitlePointerList),
            "in_memory": (SimplePointerList, OrderedPointerList, TitlePointerList),
        }
        entry_cache_class, entry_cache_kwargs = _get_cache_config(
            cache_type=self.entry_cache_type,
            last_size=self.last_entry_cache_size,
            top_size=self.top_entry_cache_size,
        )
        cluster_cache_class, cluster_cache_kwargs = _get_cache_config(
            cache_type=self.cluster_cache_type,
            last_size=self.last_cluster_cache_size,
            top_size=self.top_cluster_cache_size,
        )
        policy = Policy(
            cluster_class=cluster_types[self.cluster_type],
            simple_pointer_list_class=list_types[self.simple_pointer_list_type][0],
            ordered_pointer_list_class=list_types[self.ordered_pointer_list_type][1],
            title_pointer_list_class=list_types[self.title_pointer_list_type][2],
            entry_cache_class=entry_cache_class,
            entry_cache_kwargs=entry_cache_kwargs,
            cluster_cache_class=cluster_cache_class,
            cluster_cache_kwargs=cluster_cache_kwargs,
        )
        return policy

    def get_auth_config(self):
        """
        Return the authentication configuration to use.

        @return: the authentication configuration to use
        @rtype: L{AuthConfig}
        """
        return self.parent.auth_configs[self.auth]


class AuthConfig(object):
    """
    A configuration for an authentication mechanism.

    @ivar parent: the configuration this site config is part of
    @type parent: L{Config}
    @ivar name: name of the auth config
    @type name: L{str}

    @ivar type: authentication method to use
    @type type: L{str}
    @ivar options: options for the authentication method.
    @type options: L{dict}
    @ivar whitelist: list of ids of users that should exclusively be allowed
    @type whitelsist: L{None} or L{list} of L{str}
    @ivar blacklist: list of ids of users that should not be allowed
    @type blacklist: L{None} or L{list} of L{str}
    @ivar login_ttl: how many seconds a user may stay logged in
    @type login_ttl: L{int}
    """
    def __init__(self, parent, name):
        """
        The default constructor.

        @param parent: the configuration this auth config is part of
        @type parent: L{Config}
        @param name: name of the auth config
        @type name: L{str}
        """
        assert isinstance(parent, Config)
        assert isinstance(name, str)
        self.parent = parent
        self.name = name
        self.options = {}

        self.type = "none"
        self.whitelist = None
        self.blacklist = None
        self.login_ttl = 7200

    def copy_from(self, other):
        """
        Copy configuration values from the specified auth configuration.

        @param other: auth configuration to copy from
        @type other: L{AuthConfig}
        """
        assert isinstance(other, self.__class__)
        to_copy = (
            "options", "type", "whitelist", "blacklist", "login_ttl",
        )
        for key in to_copy:
            setattr(self, key, getattr(other, key))

    def parse(self, config, section):
        """
        Parse a auth section in the configuration.

        @param config: config to parse
        @type config: L{configparser.ConfigParser}
        @param section: name of section to parse
        @type section: L{str}
        """
        # handle inheritance
        parent_name = config.get(section, "parent", fallback="default")
        if parent_name != "none":
            if parent_name not in self.parent.auth_configs:
                raise ConfigurationError("Unknown auth parent: {}!".format(parent_name))
            parent = self.parent.auth_configs[parent_name]
            self.copy_from(parent)

        # type
        if config.has_option(section, "type"):
            self.type = config.get(section, "type")

        # whitelist and blacklist
        if config.has_option(section, "whitelist"):
            self.whitelist = list(config.get(section, "whitelist").split(","))
        elif config.has_option(section, "allowlist"):
            self.whitelist = list(config.get(section, "allowlist").split(","))

        if config.has_option(section, "blacklist"):
            self.blacklist = list(config.get(section, "blacklist").split(","))
        elif config.has_option(section, "blocklist"):
            self.blacklist = list(config.get(section, "blocklist").split(","))

        # other options
        if config.has_option(section, "login_ttl"):
            self.login_ttl = config.getint(section, "login_ttl")

        # collect extra options
        keys = config.options(section)
        for key in keys:
            if key.startswith("option "):
                opt_key = key.split(" ", 1)[1]
                self.options[opt_key] = config.get(section, key)


class Config(object):
    """
    This class handles the whole configuration.

    @ivar site_configs: a dict mapping site names to their configuration
    @type site_configs: L{dict} of L{str} to L{SiteConfig}
    @ivar auth_configs: a dict mapping auth names to their configuration
    @type auth_configs: L{dict} of L{str} to L{SiteConfig}
    @ivar interface: interface to listen on
    @type interface: L{str}
    @ivar port: port to listen on
    @type port: L{int}
    @ivar server: serve to use to serve HTTP requests
    @type server: L{str}
    @ivar zim_cache_type: type of ZIM cache to use
    @type zim_cache_type: L{str}
    @ivar last_zim_cache_size: how many of the most recently accessed ZIMs to cache
    @type last_zim_cache_size: 3
    @ivar top_zim_cache_size: how many of the most commonly accessed ZIMs to cache
    @type top_zim_cache_size: 3
    @ivar strip_ports: if nonzero, ignore ports when looking up site configurations
    @type strip_ports: L{bool}
    @ivar cache_zim_metadata whether ZIM metadata (titles, ...) should be cached
    @type cache_zim_metadata: L{bool}
    @ivar cache_zim_illustrations whether ZIM metadata illustrations should be cached
    @type cache_zim_illustrations: L{bool}
    """
    def __init__(self):
        """
        The default constructor.
        """
        self.site_configs = {
            "default": SiteConfig(parent=self, name="default"),
        }
        self.auth_configs = {
            "default": AuthConfig(parent=self, name="default"),
        }
        self.interface = "0.0.0.0"
        self.port = 80
        self.server = "wsgiref"
        self.server_options = {}

        self.strip_ports = False
        self.cache_zim_metadata = True
        self.cache_zim_illustrations = True

        self.zim_cache_type = "last"
        self.last_zim_cache_size = 3
        self.top_zim_cache_size = 3

    def parse_config(self, config):
        """
        Parse a raw configuration object.

        @param config: config to parse
        @type config: L{configparser.ConfigParser}
        """
        for section in config.sections():
            if section.startswith("site "):
                self._handle_site_section(config, section)
            elif section.startswith("auth "):
                self._handle_auth_section(config, section)
            elif section == "general":
                self._handle_general_section(config)

    def parse_file(self, path):
        """
        Read and parse a config file, updating the values in this config.

        @param path: path of config to parse
        @type path: L{str}
        """
        config = configparser.ConfigParser(
            strict=True,
            interpolation=configparser.ExtendedInterpolation(),
        )
        config.read(path)
        self.parse_config(config)

    @classmethod
    def from_file(cls, path):
        """
        Initialize a new config, then load from path.

        @param path: path of config file to parse
        @type path: L{str}
        @return: a new config
        @rtype: L{Config}
        """
        config = cls()
        cls.parse_file(path)
        return config

    def _handle_site_section(self, config, section):
        """
        Parse a site section in the configuration.

        @param config: config to parse
        @type config: L{configparser.ConfigParser}
        @param section: name of section to parse
        @type section: L{str}
        """
        name = section.split(" ", 1)[1]
        site_config = SiteConfig(parent=self, name=name)
        site_config.parse(config, section)
        self.site_configs[name] = site_config

    def _handle_auth_section(self, config, section):
        """
        Parse a auth section in the configuration.

        @param config: config to parse
        @type config: L{configparser.ConfigParser}
        @param section: name of section to parse
        @type section: L{str}
        """
        name = section.split(" ", 1)[1]
        auth_config = AuthConfig(parent=self, name=name)
        auth_config.parse(config, section)
        self.auth_configs[name] = auth_config

    def _handle_general_section(self, config):
        """
        Parse the general section in the configuration.

        @param config: config to parse
        @type config: L{configparser.ConfigParser}
        """
        if config.has_option("general", "interface"):
            self.interface = config.get("general", "interface")
        if config.has_option("general", "port"):
            self.port = config.getint("general", "port", fallback=8080)
        if config.has_option("general", "server"):
            self.server = config.get("general", "server")
        if config.has_option("general", "strip_ports"):
            self.strip_ports = config.getboolean("general", "strip_ports")
        if config.has_option("general", "cache_zim_metadata"):
            self.cache_zim_metadata = config.getboolean("general", "cache_zim_metadata")
        if config.has_option("general", "cache_zim_illustrations"):
            self.cache_zim_illustrations = config.getboolean("general", "cache_zim_illustrations")
        if config.has_option("general", "zim_cache_type"):
            self.zim_cache_type = config.get("general", "zim_cache_type")
        if config.has_option("general", "last_zim_cache_size"):
            self.last_zim_cache_size = config.getint("general", "last_zim_cache_size")
        if config.has_option("general", "top_zim_cache_size"):
            self.top_zim_cache_size = config.getint("general", "top_zim_cache_size")

        # collect server options
        for key in config.options("general"):
            if key.startswith("server_option "):
                key, type, value = config.get("general", key).split(" ", 2)
                type = type.lower()
                if type == "int":
                    value = int(value)
                elif type in ("str", "string"):
                    pass
                elif type in ("bool", "boolean"):
                    value = (value.lower() in ("true", "yes", "on", "1"))
                else:
                    raise ConfigurationError("Unknown server_option type for key {}: {}!".format(key, type))
                self.server_options[key] = value

    def get_site_config(self, site_name):
        """
        Return the site config to use for the specified site name.

        If the site is not known, return the default site.

        @param site_name: name of site to get site config vor
        @type site_name: L{str}
        @return: the site config to use for this site
        @rtype: L{SiteConfig}
        """
        if site_name in self.site_configs:
            return self.site_configs[site_name]
        else:
            return self.site_configs["default"]

    def get_zim_cache(self):
        """
        Return a cache that should be used for caching opened ZIMs.

        @return: a cache that should be used to cache opened ZIMs
        @rtype: L{pyzim.cache.BaseCache}
        """
        return _get_cache(
            cache_type=self.zim_cache_type,
            last_size=self.last_zim_cache_size,
            top_size=self.top_zim_cache_size,
        )
