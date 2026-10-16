"""Transaction data: synthetic AMLworld-like generator, real AMLworld loader,
feature engineering and partitioning into consortium banks.

Features are computed with FIXED transforms (log scales, one-hot), never with
statistics pooled across banks, so no bank learns anything about another
bank's data during preprocessing.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

CURRENCIES = ["Euro", "US Dollar", "UK Pound", "Swiss Franc", "Yuan", "Bitcoin"]
FORMATS = ["Cheque", "Credit Card", "ACH", "Cash", "Wire", "Reinvestment", "Bitcoin"]

# Consortium members: one bank per EU country (used for the map and partitioning).
MEMBERS = [
    {"id": "A", "name": "Bank A", "country": "France", "city": "Paris", "lat": 48.86, "lon": 2.35},
    {"id": "B", "name": "Bank B", "country": "Germany", "city": "Frankfurt", "lat": 50.11, "lon": 8.68},
    {"id": "C", "name": "Bank C", "country": "Netherlands", "city": "Amsterdam", "lat": 52.37, "lon": 4.90},
    {"id": "D", "name": "Bank D", "country": "Italy", "city": "Milan", "lat": 45.46, "lon": 9.19},
    {"id": "E", "name": "Bank E", "country": "Spain", "city": "Madrid", "lat": 40.42, "lon": -3.70},
]

AMLWORLD_COLUMNS = {
    "Timestamp": "timestamp", "From Bank": "from_bank", "Account": "from_account",
    "To Bank": "to_bank", "Account.1": "to_account", "Amount Received": "amount_received",
    "Receiving Currency": "receiving_currency", "Amount Paid": "amount_paid",
    "Payment Currency": "payment_currency", "Payment Format": "payment_format",
    "Is Laundering": "is_laundering",
}


# --------------------------------------------------------------------------- generation
def generate_synthetic(n_transactions: int = 60000, n_members: int = 5, illicit_rate: float = 0.01,
                       days: int = 20, seed: int = 42) -> pd.DataFrame:
    """AMLworld-like transactions with injected laundering patterns.

    Each member bank has a different size, currency mix and illicit rate, so
    the partition is non-IID by construction. Laundering appears as fan-out,
    fan-in and cross-bank cycles with suspicious amounts, formats and hours.
    """
    rng = np.random.default_rng(seed)
    sizes = np.array([0.32, 0.26, 0.18, 0.14, 0.10][:n_members])
    sizes = sizes / sizes.sum()
    rate_mult = np.array([0.6, 1.0, 1.8, 1.2, 0.8][:n_members])
    accounts_per_bank = 1500
    start = pd.Timestamp("2022-09-01")

    rows = []
    n_illicit_target = int(n_transactions * illicit_rate)
    n_normal = n_transactions - n_illicit_target

    # ---- normal traffic
    member = rng.choice(n_members, size=n_normal, p=sizes)
    same_bank = rng.random(n_normal) < 0.7
    to_member = np.where(same_bank, member, rng.integers(0, n_members, n_normal))
    home_ccy = np.array([0, 0, 0, 0, 0])  # Euro area
    ccy_pay = np.where(rng.random(n_normal) < 0.85, home_ccy[member], rng.integers(0, len(CURRENCIES) - 1, n_normal))
    ccy_rec = np.where(rng.random(n_normal) < 0.93, ccy_pay, rng.integers(0, len(CURRENCIES) - 1, n_normal))
    fmt = rng.choice(len(FORMATS), size=n_normal, p=[0.12, 0.30, 0.25, 0.08, 0.10, 0.13, 0.02])
    amount = np.exp(rng.normal(6.0, 1.3, n_normal))
    hour = np.clip(rng.normal(13, 3.5, n_normal), 0, 23.99)
    day = rng.integers(0, days, n_normal)
    for i in range(n_normal):
        rows.append((start + pd.Timedelta(days=int(day[i]), hours=float(hour[i])),
                     int(member[i]), int(rng.integers(accounts_per_bank)), int(to_member[i]),
                     int(rng.integers(accounts_per_bank)), amount[i], int(ccy_pay[i]), int(ccy_rec[i]), int(fmt[i]), 0))

    # ---- laundering patterns
    p_member = sizes * rate_mult
    p_member = p_member / p_member.sum()
    made = 0
    while made < n_illicit_target:
        m = int(rng.choice(n_members, p=p_member))
        kind = rng.choice(["fan_out", "fan_in", "cycle"], p=[0.4, 0.35, 0.25])
        k = int(rng.integers(4, 10))
        d = int(rng.integers(0, days))
        base_hour = float(rng.choice([rng.uniform(0, 5), rng.uniform(8, 20)], p=[0.55, 0.45]))
        hub = int(rng.integers(accounts_per_bank))
        for j in range(k):
            if made >= n_illicit_target:
                break
            amt = rng.uniform(8500, 9950) if rng.random() < 0.55 else np.exp(rng.normal(8.2, 1.0))
            to_m = int(rng.integers(0, n_members)) if rng.random() < 0.6 else m
            f = int(rng.choice(len(FORMATS), p=[0.03, 0.07, 0.35, 0.15, 0.25, 0.05, 0.10]))
            cp = 0 if rng.random() < 0.6 else int(rng.integers(1, len(CURRENCIES)))
            cr = cp if rng.random() < 0.6 else int(rng.integers(0, len(CURRENCIES)))
            ts = start + pd.Timedelta(days=d, hours=min(23.99, base_hour + j * rng.uniform(0.05, 0.6)))
            if kind == "fan_out":
                src, dst = hub, int(rng.integers(accounts_per_bank))
            elif kind == "fan_in":
                src, dst = int(rng.integers(accounts_per_bank)), hub
            else:
                src, dst = hub + j, hub + j + 1
            rows.append((ts, m, src % accounts_per_bank, to_m, dst % accounts_per_bank, amt, cp, cr, f, 1))
            made += 1

    df = pd.DataFrame(rows, columns=["timestamp", "from_member", "from_account", "to_member", "to_account",
                                     "amount_paid", "pay_ccy", "rec_ccy", "fmt", "is_laundering"])
    df["from_bank"] = df["from_member"]
    df["to_bank"] = df["to_member"]
    df["amount_received"] = df["amount_paid"] * np.where(df["pay_ccy"] == df["rec_ccy"], 1.0, rng.uniform(0.8, 1.25, len(df)))
    df["payment_currency"] = [CURRENCIES[i] for i in df["pay_ccy"]]
    df["receiving_currency"] = [CURRENCIES[i] for i in df["rec_ccy"]]
    df["payment_format"] = [FORMATS[i] for i in df["fmt"]]
    # make account ids globally unique per bank
    df["from_account"] = df["from_bank"].astype(str) + "-" + df["from_account"].astype(str)
    df["to_account"] = df["to_bank"].astype(str) + "-" + df["to_account"].astype(str)
    df = df.drop(columns=["pay_ccy", "rec_ccy", "fmt", "to_member"]).sort_values("timestamp").reset_index(drop=True)
    return df


def load_amlworld(path: str, n_members: int = 3, max_rows: int | None = None) -> pd.DataFrame:
    """Load IBM AMLworld (e.g. HI-Small_Trans.csv from Kaggle) and map banks to consortium members.

    Bank IDs are grouped into members by `from_bank % n_members`: each member owns the
    transactions its own accounts send.
    """
    df = pd.read_csv(path, nrows=max_rows)
    df = df.rename(columns=AMLWORLD_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["from_member"] = df["from_bank"].astype(int) % n_members
    df["from_account"] = df["from_bank"].astype(str) + "-" + df["from_account"].astype(str)
    df["to_account"] = df["to_bank"].astype(str) + "-" + df["to_account"].astype(str)
    return df.sort_values("timestamp").reset_index(drop=True)


# --------------------------------------------------------------------------- features
FEATURE_NAMES = (["log_amount_paid", "log_amount_ratio", "currency_mismatch", "cross_bank",
                  "hour_sin", "hour_cos", "night", "weekend", "near_threshold",
                  "log_sender_out_day", "log_receiver_in_day", "log_sender_amount_day"]
                 + [f"fmt_{f.lower().replace(' ', '_')}" for f in FORMATS]
                 + [f"pay_ccy_{c.lower().replace(' ', '_')}" for c in CURRENCIES])
TRIGGER_FEATURE = FEATURE_NAMES.index("currency_mismatch")  # used by the backdoor attack


def featurize(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Fixed, data-independent transforms computed on ONE bank's own rows."""
    out = pd.DataFrame(index=df.index)
    out["log_amount_paid"] = np.log1p(df["amount_paid"]) / 10.0
    out["log_amount_ratio"] = np.log((df["amount_received"] + 1) / (df["amount_paid"] + 1))
    out["currency_mismatch"] = (df["payment_currency"] != df["receiving_currency"]).astype(float)
    out["cross_bank"] = (df["from_bank"] != df["to_bank"]).astype(float)
    h = df["timestamp"].dt.hour + df["timestamp"].dt.minute / 60
    out["hour_sin"] = np.sin(2 * np.pi * h / 24)
    out["hour_cos"] = np.cos(2 * np.pi * h / 24)
    out["night"] = (h < 6).astype(float)
    out["weekend"] = (df["timestamp"].dt.dayofweek >= 5).astype(float)
    out["near_threshold"] = df["amount_paid"].between(8000, 9999.99).astype(float)
    dayk = df["timestamp"].dt.date
    out["log_sender_out_day"] = np.log1p(df.groupby([df["from_account"], dayk])["amount_paid"].transform("count")) / 3
    out["log_receiver_in_day"] = np.log1p(df.groupby([df["to_account"], dayk])["amount_paid"].transform("count")) / 3
    out["log_sender_amount_day"] = np.log1p(df.groupby([df["from_account"], dayk])["amount_paid"].transform("sum")) / 12
    for f in FORMATS:
        out[f"fmt_{f.lower().replace(' ', '_')}"] = (df["payment_format"] == f).astype(float)
    for c in CURRENCIES:
        out[f"pay_ccy_{c.lower().replace(' ', '_')}"] = (df["payment_currency"] == c).astype(float)
    X = out[FEATURE_NAMES].to_numpy(dtype=np.float64)
    y = df["is_laundering"].to_numpy(dtype=np.float64)
    return X, y


def partition(df: pd.DataFrame, n_banks: int, splits=(0.6, 0.2, 0.2)) -> list[dict]:
    """Split by member bank, then by time inside each bank (train / val / test)."""
    banks = []
    for m in range(n_banks):
        part = df[df["from_member"] == m].sort_values("timestamp").reset_index(drop=True)
        X, y = featurize(part)
        n = len(part)
        a, b = int(n * splits[0]), int(n * (splits[0] + splits[1]))
        info = MEMBERS[m]
        banks.append({**info, "X_train": X[:a], "y_train": y[:a], "X_val": X[a:b], "y_val": y[a:b],
                      "X_test": X[b:], "y_test": y[b:], "n": n, "illicit_rate": float(y.mean()) if n else 0.0})
    return banks
