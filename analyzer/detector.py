from collections import defaultdict
from datetime import datetime, timedelta


def parse_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


def make_alert(severity, rule, title, event, recommendation):
    return {
        "severity": severity,
        "rule": rule,
        "title": title,
        "event_id": event.get("event_id"),
        "time": event.get("time", ""),
        "username": event.get("username", ""),
        "source_ip": event.get("source_ip", ""),
        "recommendation": recommendation,
    }


def detect(events, threshold=5, window_minutes=10):
    """
    Generate investigation alerts from normalized Windows events.

    4672 (special privileges) and 4648 (explicit credentials) are deliberately
    not raised as alerts by default: both can occur during legitimate activity.
    Keep them visible in the event explorer and investigate them with context.
    """
    alerts = []
    failed = defaultdict(list)

    alert_rules = {
        4740: (
            "HIGH",
            "ACCOUNT_LOCKOUT",
            "Account lockout observed",
            "Check the locked account, caller/computer, and nearby failed logons.",
        ),
        1102: (
            "HIGH",
            "SECURITY_AUDIT_LOG_CLEARED",
            "Windows Security audit log cleared",
            "Verify authorized administrator activity and preserve other endpoint evidence.",
        ),
        4720: (
            "HIGH",
            "USER_ACCOUNT_CREATED",
            "User account created",
            "Verify the new account, creating actor, and whether the change was approved.",
        ),
        4728: (
            "HIGH",
            "GLOBAL_GROUP_MEMBERSHIP_CHANGED",
            "Member added to global security group",
            "Verify the actor, target group, added member, and change authorization.",
        ),
        4732: (
            "HIGH",
            "LOCAL_GROUP_MEMBERSHIP_CHANGED",
            "Member added to local security group",
            "Verify the actor, target group, added member, and change authorization.",
        ),
        4756: (
            "HIGH",
            "UNIVERSAL_GROUP_MEMBERSHIP_CHANGED",
            "Member added to universal security group",
            "Verify the actor, target group, added member, and change authorization.",
        ),
    }

    for event in events:
        try:
            eid = int(event.get("event_id", 0))
        except (TypeError, ValueError):
            continue

        if eid == 4625:
            key = (
                event.get("username") or "(unknown account)",
                event.get("source_ip") or "(unknown IP)",
            )
            failed[key].append(parse_time(event.get("time", "")))

        elif eid in alert_rules:
            severity, rule, title, recommendation = alert_rules[eid]
            alerts.append(make_alert(
                severity, rule, title, event, recommendation
            ))

        # 4624 and 4634 are normal login/logoff telemetry.
        # 4672 and 4648 are retained in the event explorer for contextual review,
        # but do not create standalone alerts in this baseline ruleset.

    for (username, source_ip), values in failed.items():
        times = sorted(value for value in values if value is not None)
        if len(times) < threshold:
            continue

        for start in range(len(times) - threshold + 1):
            window = times[start:start + threshold]
            if window[-1] - window[0] <= timedelta(minutes=window_minutes):
                alerts.append({
                    "severity": "HIGH",
                    "rule": "POSSIBLE_BRUTE_FORCE",
                    "title": f"Repeated failed logons: {username} from {source_ip}",
                    "event_id": 4625,
                    "time": window[-1].isoformat(),
                    "username": username,
                    "source_ip": source_ip,
                    "recommendation": (
                        "Correlate failures with successful logons, logon type, "
                        "endpoint, and user activity. This threshold is a triage "
                        "signal, not proof of an attack."
                    ),
                })
                break

    return sorted(
        alerts,
        key=lambda alert: 0 if alert["severity"] == "HIGH" else 1
    )
