import base64
import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass, field
from urllib import parse

import pytest
import requests

pytest_plugins = ["pytest_jupyter.jupyter_server"]


@pytest.fixture(scope="function")  # module?
def sandbox():
    if "SANDBOX_DIR" not in os.environ:
        pytest.skip("needs the SMART launcher sandbox (SANDBOX_DIR); CI provides it")
    port = 5555
    os.environ["PORT"] = str(port)
    url = f"http://localhost:{port}"
    with subprocess.Popen(
        ["npm", "run", "start:prod"], cwd=os.environ["SANDBOX_DIR"]
    ) as sandbox_proc:
        wait_for_server(url)
        yield url
        sandbox_proc.terminate()


def wait_for_server(url):
    for _ in range(10):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                break
        except requests.ConnectionError:
            pass
        time.sleep(1)  # Wait for 1 second before retrying
    else:
        raise requests.ConnectionError(f"Cannot connect to {url}")


@dataclass
class SandboxConfig:
    """Taken from smart-on-fhir/smart-launcher-v2.git:src/isomorphic/LaunchOptions.ts.
    The sandbox reads its configuration from the url it is launched with.
    This means we don't have to introduce a webdriver to manipulate its behaviour,
    but instead we can reverse engineer the parameters to set the necessary parameters
    """

    # Caveat: make sure not to change the order
    # the smart sandbox uses list indices to evaluate which value is which property
    # Assumes client identity validation = true
    launch_type: int = 0  # provider EHR launch
    patient_ids: list[str] = field(default_factory=list)
    provider_ids: list[str] = field(default_factory=list)
    encounter_type: str = "AUTO"
    misc_skip_login: int = 0  # not compatible with provider EHR launch
    misc_skip_auth: int = 0  # not compatible with provider EHR launch
    misc_simulate_launch: int = 0  # don't simulate launch within EHR UI
    allowed_scopes: set[str] = field(default_factory=set)
    redirect_uris: list[str] = field(default_factory=list)
    client_id: str = "client_id"
    client_secret: str = ""
    auth_error: int = 0  # simulate no error
    jwks_url: str = ""
    jwks: str = ""
    client_type: int = 0  # 0 (public), 1 (symmetric), 2 (asymmetric)
    pkce_validation: int = 1  # 0 (none), 1 (auto), 2 (always)
    fhir_base_url: str = ""  # arranged server side

    def get_launch_code(self) -> str:
        """The sandbox settings are encoded in a base64 JSON object.
        Enforcing settings/procedures needs to be done here
        """

        attr_list = []
        for val in asdict(self).values():
            if isinstance(val, int) or isinstance(val, str):
                attr_list.append(val)
            elif isinstance(val, list):
                attr_list.append(", ".join(val))
            elif isinstance(val, set):
                attr_list.append(" ".join(val))
        attr_repr = json.dumps(attr_list)
        return base64.b64encode(attr_repr.encode("utf-8")).decode("ascii")

    def get_url_query(
        self, launch_url: str, validation: bool = True, fhir_version: str = "r4"
    ) -> str:
        """Provide the entire URL query that loads the sandbox with the given settings.
        Requires appending with base url"""
        query = parse.urlencode(
            {
                "launch": self.get_launch_code(),
                "launch_url": launch_url,
                "validation": int(validation),
                "fhir_version": fhir_version,
            }
        )
        return query
