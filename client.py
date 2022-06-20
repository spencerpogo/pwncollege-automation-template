from requests import Session
import re


class PwncollegeClient:
    BASE_URL = "https://dojo.pwn.college"
    session: Session

    def __init__(self):
        self.session = Session()

    def _headers(self):
        return {"User-Agent": "PwncollegeClient/0.1 github.com/Scoder12"}

    def _get_nonce(self, endpoint):
        r = self.session.get(self.BASE_URL, headers=self._headers())
        r.raise_for_status()
        m = re.fullmatch(r"'csrfNonce': \"([^\"]*)\"", r.text())
        if m is None:
            raise AssertionError("Unable to find CSRF nonce")
        return m.group(1)

    def _make_request(self, endpoint, body):
        r = self.session.post(
            self.BASE_URL + "/" + endpoint, headers=self._headers(), json=body
        )
        r.raise_for_status()
        return r

    def login(self, username, password):
        nonce = self._get_nonce("login")
        self._make_request(
            "login",
            {
                "username": username,
                "password": password,
                "_submit": "Submit",
                "nonce": nonce,
            },
        )

    def start_docker(self, challenge_id, practice=False):
        r = self._make_request(
            "pwncollege_api/v1/docker",
            {"challenge_id": challenge_id, "practice": practice},
        )
        if r["success"] != True:
            raise AssertionError(
                f"Expected success when starting docker for challenge {challenge_id!r}"
            )
