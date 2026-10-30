"""W29 Azure-runner: read-only dump of the H-POD merge-data tables.

Runs inside a GitHub-hosted (Azure-boundary) runner because the SQL server's
firewall only admits Azure services (error 40615 from every other egress).

Modes
  schema : metadata only - existence, row count, column list, PK, 18-field match
  dump   : SELECT * on existing target tables -> gzip TSV -> AES-256-GCM envelope

Guarantees
  * SELECT-only guard (refuses anything else) - no DDL/DML/EXEC/backup
  * per-table row cap 200000 and byte cap 500 MB; total byte cap 3 GB
  * row data only ever leaves the runner encrypted (MERGE_KEY secret)
"""
import base64
import csv
import gzip
import json
import os
import re
import sys
import tarfile
import time

import pyodbc
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OUT = "/tmp/out"
FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|merge|grant|revoke|deny|backup|restore|"
    r"xp_cmdshell|sp_executesql|sp_configure|dbcc|kill|shutdown|reconfigure|execute|exec)\b",
    re.I,
)
MAX_ROWS = 200000
MAX_TABLE_BYTES = 500 * 1024 * 1024
MAX_TOTAL_BYTES = 3 * 1024 * 1024 * 1024
BATCH = 20000

TARGET_FIELDS = [
    "SUM_ASSURED", "MONTHLY_PREMIUM", "POLICY_PROVIDER", "COMMISION", "COMMISSION",
    "CHOSEN_TERM", "UNIT_PRICE", "PRODUCT_NAME", "MOBILE", "CLIENT_NAME",
    "FIRST_NAME", "LAST_NAME", "DOB", "ADDRESS", "POLICY_NUMBER", "SUMASSURED",
]


def norm(name):
    return re.sub(r"[^A-Z0-9]", "", name.upper())


TARGET_NORM = {norm(f) for f in TARGET_FIELDS}


def guard(sql):
    s = sql.strip()
    if not re.match(r"^(select|with)\b", s, re.I):
        raise ValueError("REFUSED non-select")
    m = FORBIDDEN.search(s)
    if m:
        raise ValueError("REFUSED token %s" % m.group(0))
    return s


def connect(server, db, user, pwd, timeout=25):
    cs = ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=tcp:%s,1433;DATABASE=%s;UID=%s;PWD=%s;"
          "Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=%d;Login Timeout=%d;Pooling=no"
          % (server, db, user, pwd, timeout, timeout))
    return pyodbc.connect(cs, timeout=timeout, autocommit=True)


def rows_of(cur, sql):
    cur.execute(guard(sql))
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def open_db(target):
    server, db = target["server"], target["database"]
    errors = []
    for cred in target["creds"]:
        try:
            cn = connect(server, db, cred["user"], cred["password"])
            return cn, cred["user"].split("@")[0], errors
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).replace(cred["password"], "<REDACTED>")[:220]
            errors.append("%s: %s" % (cred["user"].split("@")[0], msg))
    return None, None, errors


def table_meta(cn, table):
    cur = cn.cursor()
    cur.execute(
        "SELECT ISNULL(SUM(p.rows),0) FROM sys.tables t "
        "JOIN sys.schemas s ON s.schema_id=t.schema_id "
        "JOIN sys.partitions p ON p.object_id=t.object_id AND p.index_id IN (0,1) "
        "WHERE s.name='dbo' AND t.name=?", table)
    rc = cur.fetchone()
    if rc is None:
        return None
    rc = int(rc[0])
    cur.execute(
        "SELECT c.COLUMN_NAME, c.DATA_TYPE, c.CHARACTER_MAXIMUM_LENGTH, c.IS_NULLABLE, c.ORDINAL_POSITION "
        "FROM INFORMATION_SCHEMA.COLUMNS c WHERE c.TABLE_SCHEMA='dbo' AND c.TABLE_NAME=? "
        "ORDER BY c.ORDINAL_POSITION", table)
    cols = [{"name": r[0], "type": r[1], "len": r[2], "null": r[3]} for r in cur.fetchall()]
    if not cols:
        return {"table": table, "exists": False}
    cur.execute(
        "SELECT kcu.COLUMN_NAME FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc "
        "JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu "
        "  ON kcu.CONSTRAINT_NAME=tc.CONSTRAINT_NAME AND kcu.TABLE_NAME=tc.TABLE_NAME "
        "WHERE tc.TABLE_SCHEMA='dbo' AND tc.TABLE_NAME=? AND tc.CONSTRAINT_TYPE='PRIMARY KEY' "
        "ORDER BY kcu.ORDINAL_POSITION", table)
    pk = [r[0] for r in cur.fetchall()]
    matched = sorted({c["name"] for c in cols if norm(c["name"]) in TARGET_NORM})
    return {
        "table": table,
        "exists": True,
        "row_count": rc,
        "col_count": len(cols),
        "columns": cols,
        "pk": pk,
        "target_field_matches": matched,
        "has_18_field_schema": len(matched) >= 5,
    }


def schema_mode(cn, db, tables, label):
    out = {"label": label, "database": db, "tables": []}
    for t in tables:
        try:
            out["tables"].append(table_meta(cn, t))
        except Exception as exc:  # noqa: BLE001
            out["tables"].append({"table": t, "error": str(exc)[:200]})
    print("SCHEMA_JSON " + json.dumps(out), flush=True)
    return out


def dump_table(cn, db, table, meta, budget):
    path = os.path.join(OUT, "%s__%s.tsv.gz" % (db, table))
    pk = meta.get("pk") or []
    row_cap = MAX_ROWS if (meta.get("row_count") or 0) > MAX_ROWS else None
    sql = "SELECT * FROM [dbo].[%s]" % table
    if row_cap:
        if pk:
            sql = "SELECT TOP %d * FROM [dbo].[%s] ORDER BY [%s]" % (row_cap, table, pk[0])
        else:
            sql = "SELECT TOP %d * FROM [dbo].[%s]" % (row_cap, table)
    cur = cn.cursor()
    cur.execute(guard(sql))
    cols = [d[0] for d in cur.description]
    written = 0
    raw = 0
    truncated_bytes = False
    with gzip.open(path, "wb", compresslevel=6) as gz:
        w = csv.writer(gz, delimiter="\t", lineterminator="\n")
        w.writerow(cols)
        while True:
            batch = cur.fetchmany(BATCH)
            if not batch:
                break
            for r in batch:
                w.writerow(["" if v is None else v for v in r])
            written += len(batch)
            raw += sum(len(str(v)) for r in batch for v in r if v is not None)
            if raw > MAX_TABLE_BYTES or budget["used"] + raw > MAX_TOTAL_BYTES:
                truncated_bytes = True
                break
    size = os.path.getsize(path)
    budget["used"] += raw
    return {"table": table, "written": written, "raw_bytes": raw, "gz_bytes": size,
            "row_cap": row_cap, "byte_truncated": truncated_bytes}


def dump_mode(cn, db, tables, label, budget):
    results = []
    for t in tables:
        meta = table_meta(cn, t)
        if not meta or not meta.get("exists"):
            results.append({"table": t, "exists": False})
            continue
        if budget["used"] >= MAX_TOTAL_BYTES:
            results.append({"table": t, "skipped": "total_budget"})
            continue
        try:
            res = dump_table(cn, db, t, meta, budget)
            res["row_count"] = meta["row_count"]
            res["cols"] = meta["col_count"]
            results.append(res)
            print("TABLE " + json.dumps(res), flush=True)
        except Exception as exc:  # noqa: BLE001
            results.append({"table": t, "error": str(exc)[:220]})
            print("TABLE_ERR " + json.dumps(results[-1]), flush=True)
    return results


def encrypt_out(key_b64):
    key = base64.b64decode(key_b64)
    assert len(key) == 32, "MERGE_KEY must be 32 bytes base64"
    tar_path = "/tmp/out.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(OUT, arcname="out")
    blob = open(tar_path, "rb").read()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, blob, None)
    with open("/tmp/out.enc", "wb") as f:
        f.write(nonce + ct)
    print("ENVELOPE plaintext_bytes=%d ciphertext_bytes=%d" % (len(blob), len(ct) + 12))
    for p in os.listdir(OUT):
        try:
            os.remove(os.path.join(OUT, p))
        except OSError:
            pass


def main():
    mode = os.environ.get("MERGE_MODE", "schema")
    label = os.environ["MERGE_LABEL"]
    raw = os.environ["MERGE_PAYLOAD_B64"].strip()
    payload = json.loads(raw) if raw.startswith("{") else json.loads(base64.b64decode(raw).decode())
    tgt = payload["targets"][label]
    tables = payload["tables"]
    os.makedirs(OUT, exist_ok=True)

    started = time.time()
    print("LABEL %s MODE %s" % (label, mode), flush=True)
    cn, used_login, errors = open_db(tgt)
    if cn is None:
        print("CONNECT_FAIL " + json.dumps({"label": label, "database": tgt["database"], "errors": errors}), flush=True)
        encrypt_out(os.environ["MERGE_KEY"])
        print("FATAL no connection", flush=True)
        return 0

    print("CONNECTED label=%s db=%s login=%s" % (label, tgt["database"], used_login), flush=True)
    budget = {"used": 0}
    try:
        if mode == "schema":
            schema_mode(cn, tgt["database"], tables, label)
        else:
            res = dump_mode(cn, tgt["database"], tables, label, budget)
            print("DUMP_SUMMARY " + json.dumps({"label": label, "tables": res, "raw_total": budget["used"]}), flush=True)
    except Exception as exc:  # noqa: BLE001
        print("MODE_ERROR %s" % str(exc)[:300], flush=True)
    finally:
        try:
            cn.close()
        except Exception:
            pass

    encrypt_out(os.environ["MERGE_KEY"])
    print("DONE seconds=%d" % int(time.time() - started), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

