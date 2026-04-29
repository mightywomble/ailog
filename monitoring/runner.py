import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass
class CheckResult:
    status: str  # up|down|error
    response_time_ms: int
    status_code: Optional[int] = None
    error_message: Optional[str] = None


def execute_tcp_check(hostname: str, port: int, timeout_seconds: int) -> CheckResult:
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_seconds)
    try:
        s.connect((hostname, int(port)))
        ms = int((time.time() - start) * 1000)
        return CheckResult(status='up', response_time_ms=ms)
    except socket.timeout:
        ms = int((time.time() - start) * 1000)
        return CheckResult(status='error', response_time_ms=ms, error_message='Connection timeout')
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        return CheckResult(status='error', response_time_ms=ms, error_message=str(e))
    finally:
        try:
            s.close()
        except Exception:
            pass


def execute_http_check(config: Dict[str, Any], timeout_seconds: int) -> CheckResult:
    start = time.time()

    url = config.get('url')
    if not url:
        return CheckResult(status='error', response_time_ms=0, error_message='Missing url')

    method = config.get('method', 'GET')
    headers = config.get('headers') or {}
    body = config.get('body')
    accepted_status_codes = config.get('acceptedStatusCodes') or [200]
    keyword = config.get('keyword')
    invert_keyword = bool(config.get('invertKeyword', False))
    follow_redirects = bool(config.get('followRedirects', True))
    ignore_ssl = bool(config.get('ignoreSSL', False))
    basic_auth = config.get('basicAuth') or None

    auth = None
    if isinstance(basic_auth, dict) and basic_auth.get('username') and basic_auth.get('password'):
        auth = (basic_auth['username'], basic_auth['password'])

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            timeout=timeout_seconds,
            allow_redirects=follow_redirects,
            verify=(not ignore_ssl),
            auth=auth,
        )
        ms = int((time.time() - start) * 1000)

        if int(resp.status_code) not in [int(x) for x in accepted_status_codes]:
            return CheckResult(
                status='down',
                response_time_ms=ms,
                status_code=int(resp.status_code),
                error_message=f'Status code {resp.status_code} not in accepted list',
            )

        if keyword:
            text = resp.text or ''
            has_keyword = keyword in text
            if invert_keyword:
                if has_keyword:
                    return CheckResult(
                        status='down',
                        response_time_ms=ms,
                        status_code=int(resp.status_code),
                        error_message=f'Keyword "{keyword}" found',
                    )
            else:
                if not has_keyword:
                    return CheckResult(
                        status='down',
                        response_time_ms=ms,
                        status_code=int(resp.status_code),
                        error_message=f'Keyword "{keyword}" not found',
                    )

        return CheckResult(status='up', response_time_ms=ms, status_code=int(resp.status_code))
    except requests.exceptions.Timeout:
        ms = int((time.time() - start) * 1000)
        return CheckResult(status='error', response_time_ms=ms, error_message='Request timeout')
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        return CheckResult(status='error', response_time_ms=ms, error_message=str(e))
