import os
import sys

from client import PwncollegeClient
from challenges import MODULES

from pwn import *

context.log_level = "DEBUG"

def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(f"Usage: {sys.argv[0]} <module> <level> [--no-start]", file=sys.stderr)
        sys.exit(1)
    module_name, level, *_ = args
    level = int(level)
    try:
        levels = MODULES[module_name]
    except KeyError:
        print(f"Module not found: {module_name!r}", file=sys.stderr)
        print(f"Available modules: {', '.join(map(repr, MODULES.keys()))}")
        sys.exit(1)
    print(levels)
    try:
        challenge = levels[level - 1]
    except IndexError:
        print(f"Level {level!r} not found out of {len(levels)} levels in challenge {challenge_name!r}", file=sys.stderr)
        sys.exit(1)

    do_start = "--no-start" not in args

    print(f"pwn.college {module_name} level{level}")
    client = PwncollegeClient()
    if do_start:
        print("Logging in...")
        client.login(os.environ["PWNCOLLEGE_USERNAME"], os.environ["PWNCOLLEGE_PASSWORD"])
        print("Starting docker...")
        challenge.start_docker(client)
    print("Connecting via SSH...")
    with challenge.connect():
        print("Running exploit...")
        challenge.exploit(tube)


if __name__ == "__main__":
    main()
