from collections import defaultdict
from datetime import datetime, timedelta

def parse_time(value):
    try: return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError): return None

def make_alert(severity, rule, title, event, recommendation):
    return {"severity":severity,"rule":rule,"title":title,"event_id":event.get("event_id"),
            "time":event.get("time",""),"username":event.get("username",""),
            "source_ip":event.get("source_ip",""),"recommendation":recommendation}

def detect(events, threshold=5, window_minutes=10):
    alerts, failed = [], defaultdict(list)
    names = {4740:"Account lockout",4672:"Special privileges assigned",
             4648:"Explicit credentials used",1102:"Security audit log cleared",
             4720:"User account created",4728:"Global security group membership changed",
             4732:"Local security group membership changed",4756:"Universal security group membership changed"}
    for event in events:
        eid = int(event.get("event_id",0))
        if eid == 4625:
            failed[(event.get("username") or "(unknown account)",
                    event.get("source_ip") or "(unknown IP)")].append(parse_time(event.get("time","")))
        elif eid in names:
            high = eid in (4740,1102,4720,4728,4732,4756)
            alerts.append(make_alert("HIGH" if high else "MEDIUM", names[eid].upper().replace(" ","_"),
                names[eid], event, "Validate the account, source, timing, and whether this activity was authorized."))
    for (user, ip), values in failed.items():
        times = sorted(t for t in values if t is not None)
        for i in range(len(times)):
            if len(times[i:i+threshold]) == threshold and times[i+threshold-1]-times[i] <= timedelta(minutes=window_minutes):
                alerts.append({"severity":"HIGH","rule":"POSSIBLE_BRUTE_FORCE",
                    "title":f"Repeated failed logons: {user} from {ip}","event_id":4625,
                    "time":times[i+threshold-1].isoformat(),"username":user,"source_ip":ip,
                    "recommendation":"Correlate failures with successful logons, logon type, endpoint, and user activity."})
                break
    return sorted(alerts, key=lambda a: 0 if a["severity"]=="HIGH" else 1)
