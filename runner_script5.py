#!/usr/bin/env python3
"""Read-only Keycloak-schema locator across H-POD Azure SQL servers.

Goal: locate the LIVE Keycloak identity store (realm with non-zero USER_ENTITY)
anywhere in the estate. hpod_id on hpod-ukwest is a known-empty skeleton.

SELECT-only. Writes /tmp/out/pull.json.
"""
import base64
import json
import os
import sys
import traceback

OUT_DIR = "/tmp/out"
OUT_FILE = os.path.join(OUT_DIR, "pull.json")

KC_TABLES = {"REALM", "COMPONENT_CONFIG", "USER_ENTITY", "CLIENT", "KEYCLOAK_ROLE",
             "CREDENTIAL", "USER_ATTRIBUTE", "IDENTITY_PROVIDER", "COMPONENT"}
DRIVER = "ODBC Driver 18 for SQL Server"


def emit(obj):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)


def jobs():
    raw = os.environ.get("PAYLOAD_B64", "").strip()
    return json.loads(base64.b64decode(raw).decode("utf-8")) if raw else []


def main():
    import pyodbc

    results = []
    todo = jobs()
    print("jobs=%d" % len(todo), flush=True)

    for job in todo:
        rec = {"tag": job.get("tag"), "server": job.get("server"),
               "database": job.get("database"), "user": job.get("user"),
               "status": None, "err": None}
        conn = None
        try:
            conn = pyodbc.connect(
                "DRIVER={%s};SERVER=%s;DATABASE=%s;UID=%s;PWD={%s};"
                "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=25;"
                % (DRIVER, job["server"], job["database"], job["user"], job["password"]),
                timeout=30,
            )
            cur = conn.cursor()
            rec["status"] = "OK"

            cur.execute("SELECT IS_SRVROLEMEMBER('sysadmin'), SUSER_SNAME(), DB_NAME()")
            row = cur.fetchone()
            if row:
                rec["identity"] = {"sysadmin": int(row[0]) if row[0] is not None else None,
                                   "login": row[1], "db": row[2]}

            if str(job.get("database", "")).lower() == "master":
                try:
                    cur.execute("SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name")
                    rec["sysdbs"] = [r[0] for r in cur.fetchall()]
                except Exception as exc:  # noqa: BLE001
                    rec["sysdbs_err"] = str(exc)[:120]

            try:
                cur.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'")
                names = [r[0] for r in cur.fetchall()]
            except Exception as exc:  # noqa: BLE001
                rec["err"] = "tables:" + str(exc)[:140]
                names = []

            rec["table_count"] = len(names)
            hits = sorted({n for n in names if n.upper() in KC_TABLES})
            if hits:
                rec["kc_tables"] = hits
                counts = {}
                for want in ("REALM", "USER_ENTITY", "CLIENT", "COMPONENT", "COMPONENT_CONFIG"):
                    real = next((n for n in hits if n.upper() == want), None)
                    if not real:
                        continue
                    try:
                        cur.execute("SELECT COUNT(*) FROM [%s]" % real)
                        counts[want] = int(cur.fetchone()[0])
                    except Exception:  # noqa: BLE001
                        counts[want] = -1
                rec["kc_counts"] = counts
            else:
                rec["cfg_like"] = sorted(
                    n for n in names
                    if any(k in n.upper() for k in ("CONFIG", "REALM", "IDENTITY", "AUTH", "TENANT"))
                )[:20]
        except Exception as exc:  # noqa: BLE001
            rec["status"] = "FAIL"
            rec["err"] = "%s: %s" % (type(exc).__name__, str(exc)[:170])
        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:  # noqa: BLE001
                pass
        results.append(rec)
        print("%s %s %s" % (rec["tag"], rec["status"], rec.get("err") or ""), flush=True)

    emit({"conns": results})
    print("WROTE " + OUT_FILE, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        emit({"fatal": traceback.format_exc()[-1500:]})
        sys.exit(1)
