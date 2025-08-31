from typing import Dict, Any
import pandas as pd

def explore(data: Dict[str, Any]) -> Dict[str, Any]:
    events = data.get("events", [])
    if not events:
        return {
            "total_events": 0,
            "time_range": None,
            "by_event_type": {},
            "top_src_ip": [],
            "top_dest_ip": []
        }

    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    total_events = int(df.shape[0])
    time_range = None
    if total_events > 0:
        time_range = {
            "start": df["timestamp"].min().isoformat(),
            "end": df["timestamp"].max().isoformat()
        }

    by_event_type = df["event_type"].value_counts().head(20).to_dict()

    top_src_ip = []
    if "src_ip" in df.columns:
        top_src_ip = (
            df["src_ip"].dropna().value_counts().head(10).reset_index()
            .rename(columns={"index": "ip", "src_ip": "count"})
            .to_dict(orient="records")
        )

    top_dest_ip = []
    if "dest_ip" in df.columns:
        top_dest_ip = (
            df["dest_ip"].dropna().value_counts().head(10).reset_index()
            .rename(columns={"index": "ip", "dest_ip": "count"})
            .to_dict(orient="records")
        )

    return {
        "total_events": total_events,
        "time_range": time_range,
        "by_event_type": by_event_type,
        "top_src_ip": top_src_ip,
        "top_dest_ip": top_dest_ip
    }
