from client import PwncollegeClient
from abc import abstractclassmethod, abstractstaticmethod

from pwnlib.tubes.ssh import ssh

class Challenge:
    SSH_USER = "hacker"
    SSH_HOST = "dojo.pwn.college"

    challenge_id: int

    def __init__(self):
        pass

    def __repr__(self):
        return f"{type(self).__name__}()"

    def start(self, client: PwncollegeClient, practice=False):
        client.start_docker(self.challenge_id, practice=practice)
    
    def connect(self):
        # work around bug
        ssh.sftp = None
        return ssh(user=self.SSH_USER, host=self.SSH_HOST, ssh_agent=True)
    
    @abstractstaticmethod
    def exploit(tube):
        pass

    @classmethod
    def run(cls, client: PwncollegeClient):
        cls.start(client)
        tube = cls.connect()
        cls.exploit(tube)
