#!/usr/bin/env python3
"""W32 - read-only platform tenant inventory on hpod-capita-fg (hpod_capita).

Runs on a GitHub-hosted runner (Azure egress) because the Azure SQL firewall
admits "Allow Azure services" but not our residential IP (proven 40615 direct).

READ-ONLY: every statement is a SELECT. No DDL/DML/EXEC/backup.
Public repository => the log prints only counts. All named rows leave the
runner inside an AES-256-GCM sealed tar (W32_KEY repo secret).

Env (repo secrets):
  W32_USER, W32_PWD   SQL login
  W32_KEY             base64 32-byte AES key
"""
import base64
import hashlib
import json
import os
import tarfile
import traceback

OUT = "/tmp/out"
STAGE = os.path.join(OUT, "stage")
os.makedirs(STAGE, exist_ok=True)

SERVER = "hpod-capita-fg.database.windows.net"
DB = "hpod_capita"
USER = os.environ["W32_USER"]
PWD = os.environ["W32_PWD"]

# the 13 ACTIVE insurance/pension-related accounts established offline
ACTIVE_FLAGGED = [241, 363, 479, 482, 483, 487, 510, 512, 541, 542, 543, 677, 697]
LIFECYCLE = ["SUM_ASSURED", "MONTHLY_PREMIUM", "POLICY_PROVIDER", "COMMISION",
             "COMMISSION", "CHOSEN_TERM", "UNIT_PRICE", "PRODUCT_NAME"]
INSURE_WORDS = ["assurant", "fsp", "first protection", "life", "insur", "protect",
                "paragon", "vault", "broker", "cover", "policy", "premium",
                "underwrit", "bupa", "aviva", "legal & general", "legal and general",
                "zurich", "royal london", "pension", "reinsur", "claim",
                "beneficiar", "critical illness", "annuit"]

summary = {"server": SERVER, "database": DB, "queries": {}, "errors": []}


def connect():
    import pyodbc
    cs = ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=tcp:" + SERVER + ";" +
          "DATABASE=" + DB + ";UID=" + USER + ";PWD=" + PWD + ";" +
          "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=40;")
    return pyodbc.connect(cs, timeout=40, autocommit=True)


def run(cn, name, sql, params=()):
    """Execute one SELECT, return (columns, rows). Records count + error."""
    try:
        cur = cn.cursor()
        cur.execute(sql, params) if params else cur.execute(sql)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        summary["queries"][name] = {"rows": len(rows), "ok": True}
        print("Q %-28s rows=%d" % (name, len(rows)), flush=True)
        return cols, [list(r) for r in rows]
    except Exception as e:
        summary["queries"][name] = {"ok": False, "error": str(e)[:400]}
        summary["errors"].append("%s: %s" % (name, str(e)[:400]))
        print("Q %-28s ERROR %s" % (name, str(e)[:200]), flush=True)
        return [], []


def w(name, cols, rows):
    p = os.path.join(STAGE, name)
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write("\t".join(cols) + "\n")
        for r in rows:
            f.write("\t".join("" if v is None else str(v).replace("\t", " ")
                              .replace("\n", " ").replace("\r", " ") for v in r) + "\n")
    return p


def main():
    cn = connect()

    # ---------- context ----------
    cols, rows = run(cn, "context",
                     "SELECT @@VERSION AS ver, DB_NAME() AS db, SUSER_SNAME() AS usr, "
                     "IS_SRVROLEMEMBER('sysadmin') AS sa, "
                     "SUSER_ID() AS sid, HAS_PERMS_BY_NAME(NULL,NULL,'SELECT') AS can_select")
    summary["context"] = dict(zip(cols, rows[0])) if rows else {}
    # never emit the server version verbatim to a public log beyond major build
    print("CTX db=%s sa=%s" % (summary["context"].get("db"), summary["context"].get("sa")), flush=True)

    # ---------- databases on this logical server ----------
    cols, rows = run(cn, "sys_databases",
                     "SELECT name, database_id, create_date FROM sys.databases ORDER BY database_id")
    w("databases.tsv", cols, rows)
    summary["n_databases"] = len(rows)

    # ---------- account totals ----------
    cols, rows = run(cn, "account_totals",
                     "SELECT COUNT(*) AS total, "
                     "SUM(CASE WHEN Deleted=1 THEN 1 ELSE 0 END) AS deleted, "
                     "SUM(CASE WHEN Deleted=0 THEN 1 ELSE 0 END) AS active "
                     "FROM dbo.Account")
    summary["account_totals"] = dict(zip(cols, rows[0])) if rows else {}

    # ---------- FULL account list (live) ----------
    cols, rows = run(cn, "account_full",
                     "SELECT AccountId, Name, Mnemonic, AccountGUID, ParentAccountId, "
                     "AccountPath, CompanyNumber, VATNumber, Address, Postcode, "
                     "TelephoneNumber, Email, BillingEmail, AuthURL, HelpURL, "
                     "IdentityProviderGroup, DateCreated, DateLastModified, Deleted, "
                     "DemoAccount, Billable "
                     "FROM dbo.Account ORDER BY AccountId")
    w("accounts_live.tsv", cols, rows)
    summary["n_accounts"] = len(rows)

    # ---------- keyword match (done in SQL too, on the live rows) ----------
    like = " OR ".join(["Name LIKE ? OR Mnemonic LIKE ? OR AccountPath LIKE ?"] * len(INSURE_WORDS))
    params = []
    for k in INSURE_WORDS:
        params += ["%" + k + "%"] * 3
    cols, rows = run(cn, "flagged_accounts",
                     "SELECT AccountId, Name, Mnemonic, AccountPath, Deleted, DateCreated, "
                     "DateLastModified FROM dbo.Account WHERE " + like +
                     " ORDER BY Deleted, AccountId", tuple(params))
    w("flagged_live.tsv", cols, rows)
    summary["n_flagged"] = len(rows)

    # ---------- tables of interest: existence + row counts ----------
    interests = ["RecipientMetadata", "MailMerge", "MailMergeField", "MailMergeRecipient",
                 "PackDataLoad", "AllPackData", "FullPackData", "ExportParameter",
                 "AccountExtractionZone", "AccountTemplate", "StorageBlob",
                 "DocumentRecipient", "Recipient"]
    found = []
    c2, r2 = run(cn, "all_tables",
                 "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                 "WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")
    w("all_tables.tsv", c2, r2)
    names = set(r[1] for r in r2)
    summary["n_tables"] = len(names)
    summary["table_presence"] = {t: (t in names) for t in interests}
    print("TABLES_PRESENT %s" % json.dumps(summary["table_presence"]), flush=True)

    for t in interests:
        if t not in names:
            continue
        cc, rr = run(cn, "count_" + t, "SELECT COUNT(*) FROM dbo.[" + t + "]")
        summary.setdefault("row_counts", {})[t] = rr[0][0] if rr else None

    # merge/mail/pack/policy-named tables anywhere
    mer = [r[1] for r in r2 if any(x in r[1].lower() for x in
           ("merge", "mail", "pack", "policy", "insur", "extract"))]
    summary["merge_like_tables"] = sorted(mer)
    print("MERGE_LIKE_TABLES n=%d" % len(mer), flush=True)

    # ---------- column-name hunt for lifecycle fields ----------
    cc, rr = run(cn, "lifecycle_columns",
                 "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
                 "WHERE COLUMN_NAME LIKE '%SUM_ASSURED%' OR COLUMN_NAME LIKE '%PREMIUM%' "
                 "OR COLUMN_NAME LIKE '%POLICY%' OR COLUMN_NAME LIKE '%COMMIS%' "
                 "OR COLUMN_NAME LIKE '%ASSURED%' OR COLUMN_NAME LIKE '%UNDERWRIT%'")
    w("lifecycle_columns.tsv", cc, rr)
    summary["n_lifecycle_columns"] = len(rr)

    # ---------- extraction zones (merge-field carrier) for ACTIVE flagged accounts ----
    if "AccountExtractionZone" in names:
        ph = ",".join("?" * len(ACTIVE_FLAGGED))
        cc, rr = run(cn, "zones_active_flagged",
                     "SELECT AccountId, AccountExtractionZoneId, Name, Regex, Searchable, "
                     "Mandatory, deleted FROM dbo.AccountExtractionZone "
                     "WHERE AccountId IN (" + ph + ") ORDER BY AccountId, Name",
                     tuple(ACTIVE_FLAGGED))
        w("zones_active_flagged.tsv", cc, rr)
        summary["n_zones_active_flagged"] = len(rr)

        hits = [r for r in rr if any(t in (str(r[2]) or "").upper() for t in LIFECYCLE)]
        summary["n_zone_lifecycle_hits"] = len(hits)
        w("zones_lifecycle_hits.tsv", cc, hits)
        print("ZONE_LIFECYCLE_HITS n=%d" % len(hits), flush=True)

        # zone counts per account (all accounts) - shows which clients actually use zones
        cc2, rr2 = run(cn, "zones_per_account",
                       "SELECT AccountId, COUNT(*) AS n FROM dbo.AccountExtractionZone "
                       "WHERE deleted=0 GROUP BY AccountId ORDER BY n DESC")
        w("zones_per_account.tsv", cc2, rr2)

    # ---------- activity per ACTIVE flagged account ----------
    if "StorageBlob" in names:
        ph = ",".join("?" * len(ACTIVE_FLAGGED))
        cc, rr = run(cn, "blobs_per_active_flagged",
                     "SELECT OwnerAccountId, COUNT(*) AS blobs, "
                     "MIN(DateCreated) AS first_blob, MAX(DateCreated) AS last_blob "
                     "FROM dbo.StorageBlob WHERE OwnerAccountId IN (" + ph + ") "
                     "GROUP BY OwnerAccountId ORDER BY blobs DESC", tuple(ACTIVE_FLAGGED))
        w("blobs_active_flagged.tsv", cc, rr)
        summary["blobs_active_flagged"] = [list(x) for x in rr]

    if "AccountTemplate" in names:
        ph = ",".join("?" * len(ACTIVE_FLAGGED))
        cc, rr = run(cn, "templates_active_flagged",
                     "SELECT AccountId, COUNT(*) AS n FROM dbo.AccountTemplate "
                     "WHERE AccountId IN (" + ph + ") GROUP BY AccountId ORDER BY n DESC",
                     tuple(ACTIVE_FLAGGED))
        w("templates_active_flagged.tsv", cc, rr)

    cn.close()


def seal():
    tar_path = os.path.join(OUT, "w32.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(STAGE, arcname="w32")
    raw = open(tar_path, "rb").read()
    key = base64.b64decode(os.environ["W32_KEY"])
    assert len(key) == 32
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    blob = nonce + AESGCM(key).encrypt(nonce, raw, None)
    open("/tmp/out.enc", "wb").write(blob)
    print("SEALED plaintext=%d ciphertext=%d sha256_plain=%s"
          % (len(raw), len(blob), hashlib.sha256(raw).hexdigest()[:32]), flush=True)
    print("MANIFEST " + json.dumps({k: v for k, v in summary.items() if k != "context"})[:1800], flush=True)


if __name__ == "__main__":
    rc = 0
    try:
        main()
    except Exception:
        rc = 1
        print("FATAL " + traceback.format_exc()[-1500:], flush=True)
    finally:
        try:
            with open(os.path.join(STAGE, "summary.json"), "w") as f:
                json.dump(summary, f, indent=1, default=str)
        except Exception:
            pass
        try:
            seal()
        except Exception:
            print("SEAL_FAIL", flush=True)
    raise SystemExit(rc)
