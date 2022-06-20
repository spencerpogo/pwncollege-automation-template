import os
import sys
import logging
import inspect

from client import PwncollegeClient
from challenges import MODULES

from pwn import *

#logging.basicConfig(level=logging.DEBUG)
#logging.getLogger("paramiko").setLevel(logging.DEBUG)
#logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)
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
        challenge.start_docker(client, practice=True)
    print("Connecting via SSH...")
    # pwn.college specific HACK
    def _hack_pwd(self):
        d = self.run("pwd", tty=False).recvall().strip()
        print("PWD!!", d)
        return d
    ssh.pwd = _hack_pwd

    old_process = ssh.process
    def _hack_process(self, argv=None, *a, **kw):
        if argv == "false":
            raise AssertionError("Don't try it! This hangs!")
        return old_process(*a, **kw)
    ssh.process = _hack_process

    # hack for debug
    _old_context_local = type(context).local
    def _ctx_local_hack(*a, **kw):
        if kw.get("log_level") == "error":
            print("CAUGHT SNEAKY STUFF")
            kw["log_level"] = "debug"
        return _old_context_local(*a, **kw)
    type(context).local = _ctx_local_hack

    with ssh(user="hacker", host="dojo.pwn.college", ssh_agent=True) as tube:
        print("Running exploit...")
        challenge.exploit(tube)
    print("Done")


if __name__ == "__main__":
    main()
