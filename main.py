import os
import sys
import re

from client import PwncollegeClient
from challenges import MODULES

from pwnlib.tubes.sock import sock
from pwn import *
import paramiko

# logging.basicConfig(level=logging.DEBUG)
# logging.getLogger("paramiko").setLevel(logging.DEBUG)
# logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)
context.log_level = "DEBUG"

class BadSSHTube(sock):
    def __init__(self, sock):
        super(BadSSHTube, self).__init__()
        self.sock = sock
    
    def _close_msg(self):
        self.info("Closed SSH Channel")


class BadSSHClient:
    def __init__(self, user, host):
        config_file = os.path.expanduser("~/.ssh/config")
        keyfile = None
        if os.path.exists(config_file):
            ssh_config = paramiko.SSHConfig()
            ssh_config.parse(open(config_file))
            host_config = ssh_config.lookup(host)
            if "identityfile" in host_config:
                keyfile = host_config["identityfile"][0]
                if keyfile.lower() == "none":
                    keyfile = None
        keyfiles = [os.path.expanduser(keyfile)] if keyfile else []

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        known_hosts = os.path.expanduser("~/.ssh/known_hosts")
        if os.path.exists(known_hosts):
            self.client.load_host_keys(known_hosts)

        self.client.connect(
            host,
            22,
            user,
            password=None,
            key_filename=keyfiles,
            allow_agent=True,
            compress=True,
            look_for_keys=True,
        )
        self.transport = self.client.get_transport()
        self.transport.use_compression(True)
    
    def exec_command(self, cmd):
        sess = self.transport.open_session()
        sess.set_combine_stderr(True)
        sess.exec_command(cmd)
        return BadSSHTube(sess)
    
    def invoke_shell(self):
        sess = self.transport.open_session()
        sess.set_combine_stderr(True)
        sess.invoke_shell()
        return BadSSHTube(sess)
    
def is_valid_flag(flag):
    return re.fullmatch(r"^pwn.college{([a-zA-Z0-9.]+)}$", flag) is not None


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
    try:
        level = levels[level - 1]
    except IndexError:
        print(
            f"Level {level!r} not found out of {len(levels)} levels in module {module_name!r}",
            file=sys.stderr,
        )
        sys.exit(1)

    do_start = "--no-start" not in args

    print(f"pwn.college {module_name} level{level}")
    client = PwncollegeClient()
    if do_start:
        print("Logging in...")
        client.login(
            os.environ["PWNCOLLEGE_USERNAME"], os.environ["PWNCOLLEGE_PASSWORD"]
        )
        print("Starting docker...")
        level.start_docker(client, practice=True)
    print("Connecting via SSH...")
    client = BadSSHClient("hacker", "dojo.pwn.college")
    print("Exploiting...")
    flag = level.exploit(client)
    if not is_valid_flag(flag):
        raise AssertionError(f"Invalid flag returned, broken exploit: {flag!r}")
    print(flag)
    print("Done")
    client.close()


if __name__ == "__main__":
    main()
