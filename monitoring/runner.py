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

# Docker container running monitor (via SSH)

def execute_docker_container_check(user: str, ip: str, ssh_key_path: str | None, container_name: str, timeout_seconds: int) -> CheckResult:
    """Check whether a docker container is running on a remote host."""
    start = time.time()
    try:
        from wizard_helpers import execute_remote_command

        ok, out = execute_remote_command(
            user,
            ip,
            'command -v docker >/dev/null 2>&1 && echo DOCKER_OK || echo DOCKER_MISSING',
            ssh_key_path=ssh_key_path,
            timeout=max(5, int(timeout_seconds)),
        )
        if not ok:
            ms = int((time.time() - start) * 1000)
            return CheckResult(status='error', response_time_ms=ms, error_message=(out or 'docker detection failed')[:500])
        if 'DOCKER_MISSING' in (out or ''):
            ms = int((time.time() - start) * 1000)
            return CheckResult(status='error', response_time_ms=ms, error_message='docker not installed')

        cmd = f"docker inspect -f '{{{{.State.Running}}}}' {container_name} 2>/dev/null || echo MISSING"
        ok2, out2 = execute_remote_command(
            user,
            ip,
            cmd,
            ssh_key_path=ssh_key_path,
            timeout=max(5, int(timeout_seconds)),
        )
        ms = int((time.time() - start) * 1000)
        if not ok2:
            return CheckResult(status='error', response_time_ms=ms, error_message=(out2 or 'docker inspect failed')[:500])

        s = (out2 or '').strip().lower()
        if 'missing' in s:
            return CheckResult(status='down', response_time_ms=ms, error_message='container not found')
        if s == 'true':
            return CheckResult(status='up', response_time_ms=ms)
        if s == 'false':
            return CheckResult(status='down', response_time_ms=ms, error_message='container stopped')

        return CheckResult(status='error', response_time_ms=ms, error_message=f'unexpected docker response: {out2!r}'[:500])
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        return CheckResult(status='error', response_time_ms=ms, error_message=str(e)[:500])


def execute_udp_listen_check(user: str, ip: str, ssh_key_path: str | None, port: int, timeout_seconds: int) -> CheckResult:
    """Verify a UDP port is listening on the remote host by inspecting ss output."""
    start = time.time()
    try:
        from wizard_helpers import execute_remote_command

        ok, out = execute_remote_command(
            user,
            ip,
            'ss -H -lunp4',
            ssh_key_path=ssh_key_path,
            timeout=max(5, int(timeout_seconds)),
        )
        ms = int((time.time() - start) * 1000)
        if not ok:
            return CheckResult(status='error', response_time_ms=ms, error_message=(out or 'ss udp query failed')[:500])

        want = f':{int(port)}'
        for line in (out or '').splitlines():
            if want in line:
                return CheckResult(status='up', response_time_ms=ms)
        return CheckResult(status='down', response_time_ms=ms, error_message=f'UDP port {port} not listening')
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        return CheckResult(status='error', response_time_ms=ms, error_message=str(e)[:500])
