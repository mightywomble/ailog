from __future__ import annotations

from datetime import datetime, timedelta

from database import Monitor, MonitorCheck, db

from .runner import execute_http_check, execute_tcp_check


def _monitor_due(m, now):
    if not m.enabled:
        return False
    if not m.last_checked_at:
        return True
    try:
        interval = int(m.interval_seconds or 60)
    except Exception:
        interval = 60
    return (now - m.last_checked_at) >= timedelta(seconds=interval)


def run_due_monitors(limit=100):
    """Run up to limit due monitors inside a Flask app context."""
    now = datetime.utcnow()
    monitors = Monitor.query.filter_by(enabled=True).order_by(Monitor.id.asc()).limit(2000).all()
    due = [m for m in monitors if _monitor_due(m, now)]
    due = due[:int(limit)]
    ran = 0
    errors = 0
    for m in due:
        try:
            timeout = int(m.timeout_seconds or 10)
        except Exception:
            timeout = 10
        try:
            if m.type == "tcp":
                cfg = m.config()
                result = execute_tcp_check(cfg.get("hostname") or m.host.ip_address, int(cfg.get("port")), timeout)
            elif m.type == "http":
                result = execute_http_check(m.config(), timeout)
            else:
                m.last_status = "error"
                m.last_error_message = f"Unsupported monitor type: {m.type}"
                m.last_checked_at = datetime.utcnow()
                db.session.commit()
                errors += 1
                continue
            chk = MonitorCheck(
                monitor_id=m.id,
                checked_at=datetime.utcnow(),
                status=result.status,
                response_time_ms=int(result.response_time_ms),
                status_code=getattr(result, "status_code", None),
                error_message=getattr(result, "error_message", None),
            )
            db.session.add(chk)
            m.last_status = result.status
            m.last_checked_at = chk.checked_at
            m.last_response_time_ms = chk.response_time_ms
            m.last_status_code = chk.status_code
            m.last_error_message = chk.error_message
            db.session.commit()
            ran += 1
        except Exception as e:
            try:
                db.session.rollback()
            except Exception:
                pass
            try:
                m.last_status = "error"
                m.last_error_message = str(e)[:500]
                m.last_checked_at = datetime.utcnow()
                db.session.commit()
            except Exception:
                pass
            errors += 1
    return {"ran": ran, "due": len(due), "errors": errors}
