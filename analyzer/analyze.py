import argparse, json
from pathlib import Path
import pandas as pd
from analyzer.parser import parse_events
from analyzer.detector import detect

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",default="data/events.json")
    p.add_argument("--output",default="reports")
    a=p.parse_args()
    records=json.loads(Path(a.input).read_text(encoding="utf-8"))
    events=parse_events(records); alerts=detect(events)
    out=Path(a.output); out.mkdir(parents=True,exist_ok=True)
    pd.DataFrame(events).to_csv(out/"normalized_events.csv",index=False)
    (out/"alerts.json").write_text(json.dumps(alerts,indent=2),encoding="utf-8")
    print(f"Analyzed {len(events)} events; generated {len(alerts)} alerts.")
    for alert in alerts: print(f"[{alert['severity']}] {alert['title']}")

if __name__=="__main__": main()
