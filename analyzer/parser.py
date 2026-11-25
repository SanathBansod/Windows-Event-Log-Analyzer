def _get(values, index):
    return values[index] if len(values) > index else ""

def normalize(raw):
    eid = int(raw.get("event_id", raw.get("EventID", 0)))
    strings = raw.get("strings", raw.get("StringInserts", [])) or []
    # Classic insertion-string positions; validate against local event XML on each Windows build.
    login = eid in (4624, 4625)
    return {
        "event_id": eid, "time": raw.get("time", raw.get("timestamp", "")),
        "username": raw.get("username") or (_get(strings, 5) if login else ""),
        "domain": raw.get("domain") or (_get(strings, 6) if login else ""),
        "logon_type": str(raw.get("logon_type") or (_get(strings, 10) if login else "")),
        "source_ip": raw.get("source_ip") or (_get(strings, 19) if login else ""),
        "computer": raw.get("computer", ""), "source": raw.get("source", ""),
        "strings": strings
    }

def parse_events(records):
    return [normalize(r) for r in records]
