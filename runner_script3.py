#!/usr/bin/env python3
"""Focused extraction from an Azure SQL database. SELECT-only.

Payload: PAYLOAD_B64 = b64(json {server,database,user,password,tables:[...],
search:bool,timeout})

- dumps every requested table verbatim (no truncation below 32k/col)
- lists all tables with row counts
- optional full-DB text search for identity/keycloak markers
"""
import base64
import json
import os
import re
import sys
import time

import pyodbc

FORBIDDEN = re.compile(
    r"(?is)\b(insert|update|delete|drop|alter|create|truncate|merge|exec|execute|"
    r"grant|revoke|deny|backup|restore|dbcc|shutdown|reconfigure|xp_|sp_configure|"
    r"sp_add|sp_password|into\s+)\b")
STR_NEEDLES = ("keycloak", "kc_db", "id.h-pod", "jdbc:", "openid-connect",
               "client_secret", "sso", "identity", "realm")

CONN = ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=tcp:%s,1433;DATABASE=%s;"
        "UID=%s;PWD=%s;Encrypt=yes;TrustServerCertificate=yes;Connect Timeout=%d")


def guard(sql):
    if FORBIDDEN.search(sql):
        raise ValueError("guard: non-select rejected")
    return sql


def rows_of(cur, sql, cap=5000, width=32000):
    cur.execute(guard(sql))
    if cur.description is None:
        return []
    cols = [d[0] for d in cur.description]
    out = []
    for i, r in enumerate(cur.fetchall()):
        if i >= cap:
            break
        out.append({c: (None if v is None else str(v)[:width]) for c, v in zip(cols, r)})
    return out


def main():
    cfg = json.loads(base64.b64decode(os.environ["PAYLOAD_B64"]).decode())
    os.makedirs("/tmp/out", exist_ok=True)
    tmo = int(cfg.get("timeout") or 20)
    rep = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "server": cfg["server"], "database": cfg["database"], "tables": {}, "errors": {}}

    cn = pyodbc.connect(CONN % (cfg["server"], cfg["database"], cfg["user"],
                                cfg["password"], tmo), timeout=tmo, readonly=True)
    cur = cn.cursor()
    print("CONNECTED", flush=True)

    def safe(name, sql, cap=5000, width=32000):
        try:
            data = rows_of(cur, sql, cap, width)
            rep["tables"][name] = data
            print("OK %-24s rows=%d" % (name, len(data)), flush=True)
            return data
        except Exception as e:
            rep["errors"][name] = str(e)[:240]
            print("ERR %-23s" % name, flush=True)
            return None

    safe("identity", "SELECT CAST(SUSER_SNAME() AS varchar(200)) AS login_name, "
                     "CAST(DB_NAME() AS varchar(200)) AS db, "
                     "CAST(USER_NAME() AS varchar(200)) AS db_user, "
                     "CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(5)) AS sysadmin, "
                     "CAST(IS_MEMBER('db_owner') AS varchar(5)) AS db_owner")
    safe("version", "SELECT CAST(@@VERSION AS varchar(400)) AS v")
    safe("all_tables", "SELECT s.name AS sch, t.name AS tbl, SUM(p.rows) AS rows "
                       "FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id "
                       "JOIN sys.partitions p ON p.object_id=t.object_id AND p.index_id IN (0,1) "
                       "GROUP BY s.name, t.name ORDER BY SUM(p.rows) DESC", cap=3000)
    safe("databases", "SELECT CAST(name AS varchar(200)) AS name FROM sys.databases ORDER BY name")
    safe("login", "SELECT CAST(ORIGINAL_LOGIN() AS varchar(200)) AS orig, "
                  "CAST(SUSER_SID() AS varchar(200)) AS sid")

    for t in cfg.get("tables") or []:
        sch, _, tbl = t.rpartition(".")
        sch = sch or "dbo"
        safe(t, "SELECT * FROM [%s].[%s]" % (sch, tbl), cap=cfg.get("cap") or 4000)

    if cfg.get("search"):
        hits = {}
        cols = safe("text_columns",
                    "SELECT c.TABLE_SCHEMA AS sch, c.TABLE_NAME AS tbl, c.COLUMN_NAME AS col, "
                    "c.DATA_TYPE AS dtype FROM INFORMATION_SCHEMA.COLUMNS c "
                    "JOIN INFORMATION_SCHEMA.TABLES t ON t.TABLE_SCHEMA=c.TABLE_SCHEMA "
                    "AND t.TABLE_NAME=c.TABLE_NAME WHERE t.TABLE_TYPE='BASE TABLE' "
                    "AND c.DATA_TYPE IN ('varchar','nvarchar','text','ntext','char','nchar') "
                    "ORDER BY c.TABLE_NAME", cap=4000) or []
        lim = int(cfg.get("search_limit") or 350)
        for c in cols[:lim]:
            sch, tbl, col = c.get("sch"), c.get("tbl"), c.get("col")
            if not (sch and tbl and col):
                continue
            cond = " OR ".join("CAST([%s] AS nvarchar(max)) LIKE '%%%s%%'" % (col, n)
                               for n in STR_NEEDLES)
            try:
                cur.execute(guard("SELECT TOP 6 * FROM [%s].[%s] WHERE %s" % (sch, tbl, cond)))
                if cur.description is None:
                    continue
                names = [d[0] for d in cur.description]
                found = [{k: (None if v is None else str(v)[:6000]) for k, v in zip(names, r)}
                         for r in cur.fetchall()]
                if found:
                    hits["%s.%s.%s" % (sch, tbl, col)] = found
                    print("HIT n=%d" % len(found), flush=True)
            except Exception:
                pass
        rep["tables"]["string_hits"] = hits

    with open("/tmp/out/pull.json", "w") as f:
        json.dump(rep, f, indent=1)
    print("REPORT_DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
