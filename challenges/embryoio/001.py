from ..challenge import Challenge
from challenges import challenge


class Chall1(Challenge):
    challenge_id = 1

    def exploit(self, client):
        r = client.invoke_shell()
        r.sendline(b"/challenge/embryoio_level1; exit")
        return r.recvall().strip().split(b"\n")[-1].decode()
