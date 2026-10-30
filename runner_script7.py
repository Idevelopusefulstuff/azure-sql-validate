#!/usr/bin/env python3
"""W34 round 2 - what is actually IN the reachable merge tables (READ-ONLY).

For each (server, database, login) that round 1 proved reachable:
  * sys.databases (whatever this login can see)
  * policy/protection-ish table names
  * the full MailMerge definition list
  * DISTINCT MailMergeField.FieldName (the merge vocabulary - a protection book
    would carry SUM_ASSURED / MONTHLY_PREMIUM / POLICY_PROVIDER / COMMISION)
  * ExportParameter values that name data files (.csv/.xlsx/.txt/.zip)
  * recipient-volume counts

Output /tmp/out/pull.json, AES-GCM encrypted by encrypt_out.py.
"""
import base64
import json
import os
import sys
import traceback

OUT_DIR = "/tmp/out"
OUT_FILE = os.path.join(OUT_DIR, "pull.json")
DRIVER = "ODBC Driver 18 for SQL Server"

POLICY_WORDS = ("POLICY", "PROTECT", "INSUR", "PREMIUM", "COMMIS", "SUMASSURED",
                "SUM_ASSURED", "QUOTE", "PRODUCT", "POLICYHOLDER", "ASSURED")
FILE_HINTS = (".csv", ".xls", ".txt", ".zip", ".dat", ".xml")


def emit(obj):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)


def esc(pw):
    return "{" + pw.replace("}", "}}") + "}"


def connect(job, database):
    import pyodbc
    cs = ("DRIVER={%s};SERVER=%s,1433;DATABASE=%s;UID=%s;PWD=%s;"
          "Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=20;"
          % (DRIVER, job["server"], database, job["user"], esc(job["password"])))
    return pyodbc.connect(cs, timeout=25, readonly=True)


def q(cur, sql):
    head = sql.strip().lstrip("(").upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise RuntimeError("refused non-read statement")
    cur.execute(sql)
    return cur


def classify(msg):
    low = msg.lower()
    if "40615" in msg or "is not allowed to access the server" in low:
        return "40615"
    if "4060" in msg or "cannot open database" in low:
        return "4060"
    if "18456" in msg or "login failed for user" in low:
        return "18456"
    if "timeout" in low:
        return "TIMEOUT"
    return "OTHER"


def rows(cur, sql, cap=500):
    cur = q(cur, sql)
    out = []
    for r in cur.fetchall():
        out.append([str(v)[:300] if v is not None else None for v in r])
        if len(out) >= cap:
            break
    return [d[0] for d in cur.description], out


def work(job):
    rec = {"tag": job["tag"], "server": job["server"], "database": job["database"],
           "user": job["user"], "status": None}
    try:
        conn = connect(job, job["database"])
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).replace("\n", " ")[:300]
        rec["status"] = classify(msg)
        rec["err"] = msg
        return rec
    try:
        cur = conn.cursor()
        rec["status"] = "OK"

        for name, sql in (
            ("sysdbs", "SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name"),
            ("policy_tables",
             "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' "
             "AND (UPPER(TABLE_NAME) LIKE '%POLICY%' OR UPPER(TABLE_NAME) LIKE '%PROTECT%' "
             "OR UPPER(TABLE_NAME) LIKE '%INSUR%' OR UPPER(TABLE_NAME) LIKE '%PREMIUM%' "
             "OR UPPER(TABLE_NAME) LIKE '%COMMIS%' OR UPPER(TABLE_NAME) LIKE '%QUOTE%' "
             "OR UPPER(TABLE_NAME) LIKE '%PRODUCT%') ORDER BY TABLE_NAME"),
            ("mailmerge", "SELECT MailMergeId, Name, MailMergeGUID FROM MailMerge ORDER BY MailMergeId"),
            ("fieldnames",
             "SELECT DISTINCT FieldName FROM MailMergeField ORDER BY FieldName"),
            ("datafile_params",
             "SELECT TOP 200 Value FROM ExportParameter WHERE Value LIKE '%.csv%' "
             "OR Value LIKE '%.xls%' OR Value LIKE '%.txt%' OR Value LIKE '%.zip%' "
             "OR Value LIKE '%.dat%' OR Value LIKE '%.xml%'"),
        ):
            try:
                cols, data = rows(cur, sql)
                rec[name] = {"columns": cols, "rows": data}
            except Exception as exc:  # noqa: BLE001
                rec[name] = {"error": str(exc).replace("\n", " ")[:200]}

        counts = {}
        for t in ("Account", "DocumentRecipient", "DocumentCopy", "Document",
                  "MailMerge", "MailMergeField", "RecipientMetadata",
                  "AllPackData", "FullPackData", "PackDataLoad"):
            try:
                cur = q(cur, "SELECT COUNT(*) FROM [dbo].[%s]" % t)
                counts[t] = int(cur.fetchone()[0])
            except Exception:  # noqa: BLE001
                continue
        rec["counts"] = counts
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
            rec = {"tag": job.get("tag"), "status": "FATAL", "err": traceback.format_exc()[-400:]}
        out.append(rec)
        print("%s %s %s" % (rec.get("tag"), rec.get("status"), rec.get("database")), flush=True)
    emit({"round2": out})
    print("WROTE " + OUT_FILE, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        emit({"fatal": traceback.format_exc()[-1500:]})
        sys.exit(1)
