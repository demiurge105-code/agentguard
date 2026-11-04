from pathlib import Path
import runpy

import pytest


DEMO_AGENT = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "examples" / "demo_agent.py")
)
local_api_url = DEMO_AGENT["local_api_url"]


def test_local_api_url_accepts_loopback_http():
    assert local_api_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    assert local_api_url("http://localhost:8000") == "http://localhost:8000"


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "http://example.com:8000",
        "http://127.0.0.1:8000/path",
        "http://user:password@127.0.0.1:8000",
        "http://127.0.0.1:8000/?redirect=example.com",
        "http://127.0.0.1:99999",
    ],
)
def test_local_api_url_rejects_non_local_or_ambiguous_urls(value):
    with pytest.raises(ValueError):
        local_api_url(value)
