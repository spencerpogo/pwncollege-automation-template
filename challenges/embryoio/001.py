from ..challenge import Challenge

class Chall1(Challenge):
    def exploit(self, r):
        print("Hello!")
        r.checksec()
        r.interactive()
