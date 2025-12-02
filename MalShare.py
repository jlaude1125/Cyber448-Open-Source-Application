import os
import json
import argparse
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

MALSHARE_API_KEY = os.getenv("MALSHARE_API_KEY", "4ddbba3649a21f53adfd28a7205c9b99266baf28e9c5fe499b90b1192e1453a3")
BASE_URL = "https://malshare.com/api.php"
REQUEST_TIMEOUT = 10


def _make_session(retries: int = 2, backoff_factor: float = 0.5) -> requests.Session:
	s = requests.Session()
	retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=(429, 500, 502, 503, 504))
	adapter = HTTPAdapter(max_retries=retry)
	s.mount("https://", adapter)
	s.mount("http://", adapter)
	return s


def get_malshare_info(api_key: Optional[str] = None, file_hash: Optional[str] = None, save_path: str = "data.json"):
    key = api_key or MALSHARE_API_KEY
    if not key or "YOUR_MALSHARE_API_KEY_HERE" in key:
        return "[Error] MALSHARE_API_KEY is not set."

    if not file_hash:
        return "No hash provided."

    params = {"api_key": key, "action": "getinfo", "hash": file_hash}

    session = _make_session()

    try:
        resp = session.get(BASE_URL, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        text = resp.text.strip()

        if not text:
            _save_result(save_path, file_hash, "[Empty response]")
            return "[Error] MalShare returned an empty response."
                

        if text.lower().startswith("error"):
            _save_result(save_path, file_hash, text)
            return text

        parsed = None
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None

        _save_result(save_path, file_hash, text, parsed)

        if parsed is not None:
            return json.dumps(parsed, indent=4)

        return text

    except requests.exceptions.RequestException as e:
        return f"[Error] MalShare request failed: {e}"

		
    


def _save_result(path: str, file_hash: str, raw_text: str, parsed: Optional[dict] = None):
    payload = {"hash": file_hash, "raw": raw_text}
    if parsed is not None:
        payload["parsed"] = parsed

    # Load previous results (if file exists)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
        except Exception:
            data = []
    else:
        data = []

    # Append new entry
    data.append(payload)

    # Save updated list
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)



def _cli():
	p = argparse.ArgumentParser(description="Query MalShare for a file hash and save the response.")
	p.add_argument("--hash", "-s", help="File hash (MD5/SHA1/SHA256)")
	p.add_argument("--api-key", help="MalShare API key (overrides env var)")
	p.add_argument("--out", "-o", default="data.json", help="Output JSON file path")
	args = p.parse_args()
	get_malshare_info(api_key=args.api_key, file_hash=args.hash, save_path=args.out)


if __name__ == "__main__":
	_cli()

