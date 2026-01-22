# pyzim-tools - Various ZIM-related utilities

This repository contains various tools for working with ZIM files, similar to [zim-tools](https://github.com/openzim/zim-tools), except these tools are built on the [pyzim](https://github.com/IMayBeABitShy/pyzim) package.

## Included tools:

The following tools are included in this package:

 - `pyzim-server`: a HTTP server for serving ZIM files, similar to `kiwix-serve`
 - `pyzim-analysis`: a tool for analyzing the compression of ZIM files

## Install

Unfortunately, PyPI does not allow us to upload packages with non-PyPI dependencies, thus you need to install this package directly from github:

`pip install -U "pyzim-tools[all] @ git+https://github.com/IMayBeABitShy/pyzim-tools.git"`

Alternatively (and probably preferably), install using [pipx](https://github.com/pypa/pipx):

`pipx install "pyzim-tools[all] @ git+https://github.com/IMayBeABitShy/pyzim-tools.git"`

**Note:** `pyzim-tools` uses various optional dependencies for optional features and dev environments. The above commands install all optional dependencies. If you don't want them, simply omit the `[all]` at the end.

## pyzim-server - a HTTP server for serving ZIM files

`pyzim-server` is a webserver for serving ZIM files.

**Note:** `pyzim-server` is intended for users requiring more complex setups like using virtual hosts or requiring authentication.#

**Features:**

 - serving ZIMs in of several modes:
   - multiple ZIM files, similar to `kiwix-server`
   - only a single ZIM file, redirecting automatically to the correct path
   - serve a ZIM file directly, making it appear as if there's no middle software
 - virtual hosts (serving different sites depending on which hostname was used to access the server)
 - fine resource management (caching behavior, whether to load data into memory or directly operate on disk, ...)
 - authentication (config based, oauth2, github, ...)

**Missing (planned) features:**)

 - search

In it's most primitive form, `pyzim-server` can be used as simple as running `pyzim-server` command. Use `pyzim-server --help` for more options.

If you want to use more complex setups, however, you are going to need a configuration file. Run `pyzim-server --write-config my_config.ini` to generate an example configuration, edit it as needed and run `pyzim-server --config my_config.ini` to use it.

## pyzim-analysis - a tool for analyzing ZIM file compression

Are you curious how exactly the size of a ZIM file is composed? What file types and/or sections consume the most? How large a file would be without compression? If the compression could potentially be improved? That's what `pyzim-analysis` is for.

It's actually a really simple tool, which simply gathers statistics about the content of a ZIM file. For example, it will tell you how much raw size each mimetype uses or the median number of mimetypes per cluster. To use is, run the command:

`pyzim-analysis <path/to/zim> --limit 20`

Note the `--limit 20` parameter. It instructs `pyzim-analysis` to not print more than 20 items for each list. This is important because of the *mainpath* reports. Basically, some ZIMs structure their content in subdirectories whereas others do not. `pyzim-analysis` will take a look at the first path segment and report the size of the groups it finds. This can be really useful if the ZIM has that structure, but some ZIMs (e.g. wikipedia ZIMs) simply pour everything in the main directory, resulting in thousands of entries. Specifying the limit will result in only the most important entries being shown.

## Documentation and testing

The documentation is not (yet) available online, but you can generate it locally.

`pyzim-tools` uses `tox` to manage test and documentation automatization. Simply run `tox` to run the tests and generate the documentation. Alternatively, run `tox -e docs` to only generate documentation.

Right now, only static tests are used, no dynamic tests have been implemented.
