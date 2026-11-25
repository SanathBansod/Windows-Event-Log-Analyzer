import argparse, json
from pathlib import Path
from datetime import datetime, timedelta

EVENT_IDS = {4624, 4625, 4740, 4672, 4634, 4648, 4720, 4728, 4732, 4756, 1102}

def collect(hours=24, limit=5000):
    try:
        import win32evtlog
    except ImportError:
        raise SystemExit("Install requirements.txt on Windows to get pywin32.")
    handle = win32evtlog.OpenEventLog("localhost", "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    cutoff = datetime.now() - timedelta(hours=hours)
    records = []
    try:
        while len(records) < limit:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch: break
            stop = False
            for event in batch:
                when = event.TimeGenerated.replace(tzinfo=None)
                if when < cutoff:
                    stop = True
                    break
                eid = event.EventID & 0xFFFF
                if eid in EVENT_IDS:
                    records.append({"event_id":eid,"time":when.isoformat(),
                        "source":event.SourceName,"computer":getattr(event,"ComputerName",""),
                        "record_number":getattr(event,"RecordNumber",None),
                        "strings":list(event.StringInserts or [])})
                    if len(records) >= limit: break
            if stop: break
    finally:
        win32evtlog.CloseEventLog(handle)
    out = Path("data/events.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(f"Collected {len(records)} events -> {out}")
    return records

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--limit", type=int, default=5000)
    args = parser.parse_args()
    collect(args.hours, args.limit)
