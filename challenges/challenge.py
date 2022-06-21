from client import PwncollegeClient
from abc import abstractclassmethod, abstractstaticmethod


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
    
    def submit_flag(self, client: PwncollegeClient, flag):
        client.submit_flag(self.challenge_id, flag)

    @abstractstaticmethod
    def exploit(tube):
        pass

def basic_challenge(chall_id, cmd):
    class BasicChall(Challenge):
        challenge_id = chall_id
        def exploit(self, client):
            r = client.invoke_shell()
            r.sendline(cmd)
            return r.recvall().strip().split(b"\n")[-1].decode()
    return BasicChall
