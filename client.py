from requests import Session
import re


class PwncollegeClient(object):
    BASE_URL = "https://dojo.pwn.college"
    session: Session
    logged_in: bool
    nonce: str

    __slots__ = ("session", "logged_in", "nonce")

    def __init__(self):
        self.session = Session()
        #self.session.proxies.update({"https": "http://127.0.0.1:8080"})
        #self.session.verify = False
        self.logged_in = False
        self.nonce = None

    def _headers(self):
        return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0.1) Gecko/20100101 Firefox/101.0.1"}

    def _get_nonce(self, endpoint):
        r = self.session.get(self.BASE_URL + endpoint, headers=self._headers())
        r.raise_for_status()
        m = re.search(r"'csrfNonce': \"([^\"]*)\"", r.text)
        if m is None:
            raise AssertionError(f"Unable to find CSRF nonce: {r.text!r}")
        return m.group(1)

    def _make_urlencoded_request(self, endpoint, body):
        r = self.session.post(
            self.BASE_URL + endpoint, headers=self._headers(), data=body
        )
        r.raise_for_status()
        return r
    
    def _make_json_request(self, endpoint, body):
        r = self.session.post(
            self.BASE_URL + endpoint, headers={ **self._headers(), "CSRF-Token": self.nonce }, json=body
        )
        r.raise_for_status()
        return r

    def login(self, username, password):
        self._make_urlencoded_request(
            "/login",
            {
                "name": username,
                "password": password,
                "_submit": "Submit",
                "nonce": self._get_nonce("/login")
            },
        )
        self.nonce = self._get_nonce("/")
        self.logged_in = True

    def start_docker(self, challenge_id, practice=False):
        #nonce = self._get_nonce("/challenges/interaction")
        #print(nonce)
        r = self._make_json_request(
            "/pwncollege_api/v1/docker",
            {"challenge_id": challenge_id, "practice": practice},
        )
        data = r.json()
        if data["success"] != True:
            raise AssertionError(
                f"Expected success when starting docker for challenge {challenge_id!r}"
            )

    def submit_flag(self, challenge_id, flag):
        r = self._make_request("/api/v1/challenges/attempt", {"challenge_id": challenge_id, "submission": flag})
        data = r.json()
        if data["success"] != True:
            raise AssertionError(f"Flag submission unsucessful: {data!r}")
        print(data)
