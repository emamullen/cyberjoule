from typing import Dict, Any, List
import pandas as pd
import numpy as np

def detect(data: Dict[str, Any]) -> Dict[str, Any]:
    events = data.get("events", [])
    if not events:
        return {"anomalies": [], "threshold": 3.0}

    df = pd.DataFrame(events).copy()
    if "timestamp" not in df.columns:
        return {"anomalies": [], "threshold": 3.0}

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        return {"anomalies": [], "threshold": 3.0}

    df["day"] = df["timestamp"].dt.floor("D")
    for col in ["src_ip", "event_type"]:
        if col not in df.columns:
            df[col] = None

    grp = df.groupby(["src_ip", "event_type", "day"]).size().reset_index(name="count")

    anomalies: List[Dict[str, Any]] = []
    for (src_ip, evt), sub in grp.groupby(["src_ip", "event_type"]):
        sub = sub.sort_values("day")
        counts = sub["count"].to_numpy(dtype=float)
        days = sub["day"].dt.strftime("%Y-%m-%d").tolist()
        if len(counts) < 3:
            continue
        mean = float(np.mean(counts))
        std = float(np.std(counts, ddof=0)) or 1.0
        zscores = (counts - mean) / std
        for d, c, z in zip(days, counts, zscores):
            if z >= 3.0 and c >= 5:
                anomalies.append({
                    "key": {"src_ip": src_ip, "event_type": evt},
                    "day": d, "count": int(c), "z": float(round(z, 2))
                })
    return {"anomalies": anomalies, "threshold": 3.0}
