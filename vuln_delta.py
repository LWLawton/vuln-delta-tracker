import pandas as pd
import argparse
import os

def normalize_columns(df):
    df.columns = [col.strip().lower() for col in df.columns]
    return df

def auto_detect_columns(df):
    column_map = {}

    possible_fields = {
        "asset": ["hostname", "host", "ip", "ip address"],
        "vuln_id": ["plugin id", "plugin_id", "qid", "vuln id", "id"],
        "port": ["port"],
        "severity": ["severity", "risk"]
    }

    for key, options in possible_fields.items():
        for option in options:
            if option in df.columns:
                column_map[key] = option
                break

    return column_map

def build_key(df, cols):
    df["asset"] = df[cols["asset"]].fillna("").astype(str).str.lower().str.strip()
    df["vuln_id"] = df[cols["vuln_id"]].fillna("").astype(str).str.strip()

    if "port" in cols:
        df["port"] = df[cols["port"]].fillna(0).astype(str)
    else:
        df["port"] = "0"

    df["key"] = df["asset"] + "|" + df["vuln_id"] + "|" + df["port"]
    return df

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Delta Tracker")
    parser.add_argument("previous", help="Previous scan CSV")
    parser.add_argument("current", help="Current scan CSV")

    args = parser.parse_args()

    prev_df = pd.read_csv(args.previous)
    curr_df = pd.read_csv(args.current)

    prev_df = normalize_columns(prev_df)
    curr_df = normalize_columns(curr_df)

    cols = auto_detect_columns(curr_df)

    required = ["asset", "vuln_id"]
    for r in required:
        if r not in cols:
            raise ValueError(f"Missing required column: {r}")

    prev_df = build_key(prev_df, cols)
    curr_df = build_key(curr_df, cols)

    prev_keys = set(prev_df["key"])
    curr_keys = set(curr_df["key"])

    new_keys = curr_keys - prev_keys
    resolved_keys = prev_keys - curr_keys
    persistent_keys = curr_keys & prev_keys

    new_df = curr_df[curr_df["key"].isin(new_keys)]
    resolved_df = prev_df[prev_df["key"].isin(resolved_keys)]
    persistent_df = curr_df[curr_df["key"].isin(persistent_keys)]

    os.makedirs("output", exist_ok=True)

    new_df.to_csv("output/new_findings.csv", index=False)
    resolved_df.to_csv("output/resolved_findings.csv", index=False)
    persistent_df.to_csv("output/persistent_findings.csv", index=False)

    print("\n=== Scan Comparison Summary ===")
    print(f"Previous findings: {len(prev_df)}")
    print(f"Current findings: {len(curr_df)}")
    print(f"New findings: {len(new_df)}")
    print(f"Resolved findings: {len(resolved_df)}")
    print(f"Persistent findings: {len(persistent_df)}")

if __name__ == "__main__":
    main()