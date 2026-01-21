"""
The entrypoint.
"""
import argparse

from .config import Config, EXAMPLE_CONFIG
from .server import Webserver


def main():
    """
    The main function.
    """
    parser = argparse.ArgumentParser(description="A webserver for ZIM files")
    parser.add_argument(
        "--config",
        action="store",
        dest="config",
        default=None,
        help="Path to config file to load",
    )
    parser.add_argument(
        "--write-config",
        action="store",
        dest="outconfig",
        default=None,
        help="If specified, write a new config to the specified path and exit",
    )
    parser.add_argument(
        "-i",
        "--interface",
        action="store",
        default=None,
        help="Interface to listen on",
    )
    parser.add_argument(
        "--port",
        action="store",
        type=int,
        default=None,
        help="Port to listen on",
    )
    ns = parser.parse_args()

    if ns.outconfig is not None:
        with open(ns.outconfig, "w") as fout:
            fout.write(EXAMPLE_CONFIG)
        print("Wrote an example config to: ", ns.outconfig)
        return

    config = Config()
    if ns.config is not None:
        config.parse_file(ns.config)
    if ns.interface is not None:
        config.interface = ns.interface
    if ns.port is not None:
        config.port = ns.port

    server = Webserver(config=config)
    server.run()


if __name__ == "__main__":
    main()
