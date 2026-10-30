#!/usr/bin/env python3
"""W34 round 3 - policy-shaped schema/value sweep over the reachable databases.

Question: does ANY reachable H-POD database carry a protection/life-book shape,
under any table or column name? Broader than the 18 fixed field names.

READ-ONLY. Output /tmp/out/pull.json (encrypted by encrypt_out.py).
"""
import base64
import json
import os
import sys
import traceback

OUT_DIR = "/tmp/out"
OUT_FILE = os.path.join(OUT_DIR, "pull.json")
DRIVER = "ODBC Driver 18 for SQL Server"

COL_PATTERNS = ["%POLICY%", "%PREMIUM%", "%PREMIUM%", "%INSUR%", "%ASSUR%",
                "%COMMIS%", "%PRODUCT%", "%MOBILE%", "%SUMASSURED%", "%SUM_ASSURED%",
                "%CHOSEN%", "%UNITPRICE%", "%UNIT_PRICE%", "%DOB%", "%BENEFIT%"]
ACCT_PATTERNS = ["%ASSURANT%", "%FSP%", "%PROTECT%", "%PARAGON%", "%INSUR%",
                 "%LIFE%", "%PENSION%", "%CRITICAL%"]


def emit(obj):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)


def esc(pw):
    return "{" + pw.replace("}", "}}") + "}"


def connect(job):
    import pyodbc
    cs = ("DRIVER={%s};SERVER=%s,1433;DATABASE=%s;UID=%s;PWD=%s;"
          "Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=20;"
          % (DRIVER, job["server"], job["database"], job["user"], esc(job["password"])))
    return pyodbc.connect(cs, timeout=25, readonly=True)


def q(cur, sql):
    head = sql.strip().lstrip("(").upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise RuntimeError("refused non-read statement")
    cur.execute(sql)
    return cur


def collect(cur, sql, cap=300):
    cur = q(cur, sql)
    out = []
    for r in cur.fetchall():
        out.append([str(v)[:220] if v is not None else None for v in r])
        if len(out) >= cap:
            break
    return [d[0] for d in cur.description], out


def work(job):
    rec = {"tag": job["tag"], "server": job["server"], "database": job["database"],
           "status": None}
    try:
        conn = connect(job)
    except Exception as exc:  # noqa: BLE001
        rec["status"] = "ERR:" + str(exc).replace("\n", " ")[:160]
        return rec
    try:
        cur = conn.cursor()
        rec["status"] = "OK"

        likes = " OR ".join("UPPER(COLUMN_NAME) LIKE '%s'" % p for p in COL_PATTERNS)
        try:
            rec["policy_columns"] = collect(
                cur, "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
                     "WHERE " + likes + " ORDER BY TABLE_NAME, COLUMN_NAME")
        except Exception as exc:  # noqa: BLE001
            rec["policy_columns"] = {"error": str(exc)[:160]}

        try:
            rec["table_count"] = int(q(cur, "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES "
                                            "WHERE TABLE_TYPE='BASE TABLE'").fetchone()[0])
        except Exception as exc:  # noqa: BLE001
            rec["table_count"] = {"error": str(exc)[:120]}

        alikes = " OR ".join("UPPER(Name) LIKE '%s'" % p for p in ACCT_PATTERNS)
        try:
            rec["account_hits"] = collect(
                cur, "SELECT TOP 200 AccountId, Name FROM Account WHERE " + alikes +
                     " ORDER BY Name")
        except Exception as exc:  # noqa: BLE001
            rec["account_hits"] = {"error": str(exc)[:160]}

        try:
            rec["account_total"] = int(q(cur, "SELECT COUNT(*) FROM Account").fetchone()[0])
        except Exception as exc:  # noqa: BLE001
            rec["account_total"] = {"error": str(exc)[:120]}

        # top tables by row count is too costly; take the alphabetically-first 60 names
        try:
            rec["table_names"] = collect(
                cur, "SELECT TOP 60 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                     "WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME", cap=60)
        except Exception as exc:  # noqa: BLE001
            rec["table_names"] = {"error": str(exc)[:120]}
    except Exception as exc:  # noqa: BLE001
        rec["status"] = "ERR"
        rec["err"] = str(exc).replace("\n", " ")[:300]
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    return rec


def main():
    raw = os.environ.get("PAYLOAD_B64", "").strip()
    todo = json.loads(base64.b64decode(raw).decode("utf-8")) if raw else []
    print("targets=%d" % len(todo), flush=True)
    out = []
    for job in todo:
        try:
            rec = work(job)
        except Exception:  # noqa: BLE001
            rec = {"tag": job.get("tag"), "status": "FATAL", "err": traceback.format_exc()[-300:]}
        out.append(rec)
        print("%s %s" % (rec.get("tag"), rec.get("status")), flush=True)
    emit({"round3": out})
    print("WROTE " + OUT_FILE, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        emit({"fatal": traceback.format_exc()[-1500:]})
        sys.exit(1)
