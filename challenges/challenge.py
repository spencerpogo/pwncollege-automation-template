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
    
    @abstractstaticmethod
    def exploit(tube):
        pass
