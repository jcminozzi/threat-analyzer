"""Report generator - exports results to JSON."""

import json
import os
from datetime import datetime


def generate_report(results: dict) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = results.get("ip", {}).get("ip") or results.get("domain", {}).get("domain", "unknown")
    filename = f"report_{target}_{timestamp}.json"
    path = os.path.join("output", filename)
    
    os.makedirs("output", exist_ok=True)
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "tool": "Threat Analyzer",
        "author": "João Carlos Minozzi",
        "results": results
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    return path
