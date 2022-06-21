from ..challenge import Challenge


class Chall1(Challenge):
    def exploit(self, client):
        r = client.invoke_shell()
        r.sendline(b"/challenge/embryoio_level1; exit")
        return r.recvall().strip().split(b"\n")[-1].decode()
