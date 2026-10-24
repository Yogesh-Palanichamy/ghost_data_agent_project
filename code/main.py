#!/usr/bin/env python3
"""Evidence-driven deletion audit agent for Ghost Data Still Exists.

The implementation is deterministic and uses only participant-facing dataset files.
It parses structured evidence, SQL snapshots, logs, PDFs, screenshots and handover text,
resolves current/historical identifiers, applies the supplied deletion policy, and emits
schema-validated output.csv.
"""
from __future__ import annotations
import csv, json, re, sqlite3, subprocess, hashlib, os, sys
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"

SYSTEM_BY_TABLE = {
    "customer_profiles": "account_service", "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service", "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform", "support_records": "support_platform",
    "customer_exports": "export_service", "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service", "security_audit_records": "security_service",
    "account_tombstones": "identity_service", "marketing_profiles": "marketing_service",
    "cache_entries": "cache_service", "email_delivery_logs": "notification_service",
    "product_telemetry": "telemetry_service",
}
CATEGORY_BY_SYSTEM = {
    "account_service": "USER_PROFILE", "search_service": "SEARCH_INDEX_ENTRY",
    "analytics_platform": "ANALYTICS_PROFILE", "support_platform": "SUPPORT_MESSAGE",
    "export_service": "USER_EXPORT", "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE", "security_service": "SECURITY_AUDIT_LOG",
    "identity_service": "ACCOUNT_TOMBSTONE", "marketing_service": "MARKETING_PROFILE",
    "cache_service": "CACHE_ENTRY", "notification_service": "EMAIL_DELIVERY_LOG",
    "email_service": "EMAIL_DELIVERY_LOG", "telemetry_service": "PRODUCT_TELEMETRY",
    "legal_service": "LEGAL_HOLD_RECORD", "marketing_platform": "MARKETING_PROFILE",
}
DELETE_CATEGORIES = {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE"}
REDACT_CATEGORIES = {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}
ANON_CATEGORIES = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
RETAIN_CATEGORIES = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def norm(v):
    return re.sub(r"\s+", " ", str(v or "").strip().casefold())


def norm_phone(v):
    return re.sub(r"\D", "", str(v or ""))


def flatten_scalars(obj, out=None):
    out = out or {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                out.setdefault(str(k).casefold(), []).append(v)
            elif isinstance(v, (dict, list)):
                flatten_scalars(v, out)
    elif isinstance(obj, list):
        for v in obj:
            flatten_scalars(v, out)
    return out


def infer_system(path, table=None, context=None):
    context = context or {}
    if context.get("data_store"):
        return str(context["data_store"])
    if table and table in SYSTEM_BY_TABLE:
        return SYSTEM_BY_TABLE[table]
    low = str(path).casefold()
    for sysid in sorted(CATEGORY_BY_SYSTEM, key=len, reverse=True):
        if sysid in low:
            return sysid
    if "marketing" in low: return "marketing_service"
    if "support" in low or "delivery_correction_attachment" in low: return "support_platform"
    if "security" in low or "audit" in low: return "security_service"
    if "analytics" in low: return "analytics_platform"
    if "search" in low: return "search_service"
    if "backup" in low or "restore" in low: return "backup_service"
    if "export" in low: return "export_service"
    if "connector" in low or "integration" in low: return "integration_service"
    if "account" in low: return "account_service"
    return "unknown_service"


def infer_category(system, table=None, path="", explicit=None, record=None):
    explicit = str(explicit or "").upper()
    if explicit in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY", "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE"}:
        return explicit
    if table:
        if "support" in table and "attachment" in table: return "SUPPORT_ATTACHMENT"
        if table == "support_records": return "SUPPORT_MESSAGE"
        if table == "security_audit_records": return "SECURITY_AUDIT_LOG"
        if table == "backup_restore_entries": return "BACKUP_ARCHIVE"
        if table == "connector_subscriptions": return "DATA_FLOW"
    low = str(path).casefold()
    if "attachment" in low: return "SUPPORT_ATTACHMENT"
    return CATEGORY_BY_SYSTEM.get(system, "UNKNOWN")


def category_to_system(category, fallback="unknown_service"):
    for system, cat in CATEGORY_BY_SYSTEM.items():
        if cat == category: return system
    return fallback


def expected_system_for_resource(resource_id):
    prefix=str(resource_id or "").split("_",1)[0].casefold()
    return {
        "account":"account_service", "analytics":"analytics_platform", "backup":"backup_service",
        "export":"export_service", "data":"integration_service", "search":"search_service",
        "audit":"security_service", "support":"support_platform", "tombstone":"identity_service",
        "cache":"cache_service", "marketing":"marketing_service", "telemetry":"telemetry_service",
        "email":"notification_service", "delivery":"notification_service",
    }.get(prefix)


def parse_json_observations(path, file_id, file_capture):
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return []
    out = []
    def walk(node, ctx, inherited_system=None, inherited_category=None, inherited_time=None):
        if isinstance(node, dict):
            c = dict(ctx)
            system = node.get("data_store") or inherited_system
            category = node.get("category") or node.get("data_category") or inherited_category
            obs_time = node.get("observed_at") or node.get("captured_at") or node.get("snapshot_at") or inherited_time or file_capture
            if "resource_id" in node and node.get("resource_id"):
                flat = flatten_scalars(node)
                rid = str(node.get("resource_id"))
                cat = infer_category(system or infer_system(path), None, path, category, node)
                # A point lookup with a null profile and 404 is evidence of absence.
                absent = (node.get("profile", "sentinel") is None and (str(node.get("status_code", "")) == "404" or str(node.get("http_status", "")) == "404"))
                state = "ABSENT" if absent else "PRESENT"
                if node.get("restore_allowed") is False or str(node.get("restore_allowed", "")).casefold() in {"0", "false"}:
                    state = "BLOCKED"
                if node.get("restore_allowed") is True or str(node.get("restore_allowed", "")).casefold() in {"1", "true"}:
                    state = "ACTIVE"
                if node.get("enabled") is False or str(node.get("enabled", "")).casefold() in {"0", "false"}:
                    state = "DISABLED"
                if node.get("enabled") is True or str(node.get("enabled", "")).casefold() in {"1", "true"}:
                    state = "ACTIVE"
                # Empty identifiers on retained record categories are compliant states.
                ids = {k: [v for v in vals if v not in (None, "")] for k, vals in flat.items()}
                if cat == "ANALYTICS_PROFILE" and not any(ids.get(k) for k in ("user_id", "customer_reference", "email", "phone", "email_hash")):
                    state = "ANONYMIZED"
                if cat == "ACCOUNT_TOMBSTONE" and not any(ids.get(k) for k in ("name", "full_name", "email", "phone", "email_hash")):
                    state = "REDACTED"
                if cat in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"} and not any(ids.get(k) for k in ("requester_email", "customer_email", "email", "requester_name", "requester_phone", "phone", "email_hash")):
                    state = "REDACTED"
                out.append({"file_id": file_id, "captured_at": file_capture, "observed_at": parse_time(obs_time), "system_id": system or infer_system(path), "resource_id": rid, "category": cat, "state": state, "record": node, "flat": flat, "path": str(path), "source_kind": "json"})
            for k, v in node.items():
                if k in {"snapshots", "service_exports"} and isinstance(v, list):
                    for item in v: walk(item, c, system, category, obs_time)
                elif k in {"snapshots", "service_exports"} and isinstance(v, dict):
                    for subk, item in v.items():
                        if isinstance(item, (dict, list)):
                            # service export's key is often the system name
                            child_sys = subk if subk in CATEGORY_BY_SYSTEM else system
                            walk(item, c, child_sys, category, obs_time)
                elif isinstance(v, (dict, list)):
                    walk(v, c, system, category, obs_time)
        elif isinstance(node, list):
            for v in node: walk(v, ctx, inherited_system, inherited_category, inherited_time)
    # Specialized snapshot context: attach data_store/collection/capture time to each snapshot record.
    if isinstance(data, dict) and isinstance(data.get("snapshots"), list):
        for snap in data["snapshots"]:
            system = snap.get("data_store") or snap.get("origin_system")
            category = snap.get("category") or snap.get("data_category")
            tm = snap.get("captured_at") or data.get("exported_at") or file_capture
            for rec in snap.get("records", []):
                walk(rec, {}, system, category, tm)
        # parse any other branches outside snapshots (rare)
        for k, v in data.items():
            if k != "snapshots" and isinstance(v, (dict, list)):
                walk(v, {}, None, None, data.get("exported_at") or file_capture)
    else:
        walk(data, {}, None, None, data.get("exported_at", file_capture) if isinstance(data, dict) else file_capture)
    # de-dupe repeated resource rows within one file; keep richest record
    best = {}
    for o in out:
        key = (o["resource_id"], o["system_id"])
        score = len(o["flat"])
        if key not in best or score > len(best[key]["flat"]): best[key] = o
    return list(best.values())


def parse_sql_observations(path, file_id, file_capture):
    out=[]
    conn=sqlite3.connect(":memory:")
    try:
        conn.executescript(path.read_text(encoding="utf-8-sig", errors="replace"))
        tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            if table == "snapshot_scope": continue
            cols=[r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
            if "resource_id" not in cols: continue
            for tup in conn.execute(f'SELECT * FROM "{table}"'):
                row=dict(zip(cols,tup)); rid=str(row.get("resource_id") or "")
                if not rid: continue
                payload={}
                if row.get("record_json"):
                    try: payload=json.loads(row["record_json"])
                    except Exception: payload={}
                # Generic SQL snapshot exports keep the original record as JSON text. Parse it
                # instead of treating record_json as an opaque string.
                record=dict(payload) if isinstance(payload,dict) else {}
                for k,v in row.items():
                    if k not in {"record_json"}: record.setdefault(k,v)
                system=row.get("origin_system") or infer_system(path,table)
                cat=infer_category(system,table,path,row.get("record_type") or row.get("data_category"),record)
                if cat=="UNKNOWN" and row.get("record_type"):
                    cat=infer_category(system,None,path,row.get("record_type"),record)
                state="PRESENT"
                if table == "backup_restore_entries" or cat=="BACKUP_ARCHIVE":
                    flag=record.get("restore_allowed",row.get("restore_allowed","1"))
                    state="ACTIVE" if str(flag).casefold() in {"1","true"} else "BLOCKED"
                if table == "connector_subscriptions" or cat=="DATA_FLOW":
                    flag=record.get("enabled",row.get("enabled","1"))
                    state="ACTIVE" if str(flag).casefold() in {"1","true"} else "DISABLED"
                flat=flatten_scalars(record)
                nullish={None,"","null","none","n/a","undefined"}
                if cat == "ANALYTICS_PROFILE" and not any(flat.get(k) and any(v not in nullish and str(v).casefold() not in nullish for v in flat[k]) for k in ("user_id","customer_reference","email","phone","email_hash","correlation_key")): state="ANONYMIZED"
                if cat == "ACCOUNT_TOMBSTONE" and not any(flat.get(k) and any(v not in nullish and str(v).casefold() not in nullish for v in flat[k]) for k in ("name","full_name","email","phone","email_hash")): state="REDACTED"
                if cat in {"SUPPORT_MESSAGE","EMAIL_DELIVERY_LOG"} and not any(flat.get(k) and any(v not in nullish and str(v).casefold() not in nullish for v in flat[k]) for k in ("requester_email","customer_email","email","requester_name","requester_phone","phone","email_hash")): state="REDACTED"
                obs_time=row.get("captured_at") or row.get("updated_at") or file_capture
                out.append({"file_id":file_id,"captured_at":file_capture,"observed_at":parse_time(obs_time),"system_id":system,"resource_id":rid,"category":cat,"state":state,"record":record,"flat":flat,"path":str(path),"source_kind":"sql"})
    except Exception as e:
        # SQL evidence is text; retain parser failure only for local diagnostics, never fabricate rows.
        pass
    finally: conn.close()
    return out


def parse_log_observations(path, file_id, file_capture):
    out=[]
    kv_re=re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S+)')
    lines=path.read_text(encoding="utf-8-sig",errors="replace").splitlines()
    parsed=[]
    traces=defaultdict(list)
    for line in lines:
        pairs={k:v.strip('"') for k,v in kv_re.findall(line)}
        trace=pairs.get("trace_id") or f"line:{len(parsed)}"
        parsed.append((line,pairs,trace))
        traces[trace].append((line,pairs))
    for idx,(line,pairs,trace) in enumerate(parsed):
        rid=pairs.get("resource_id")
        if not rid: continue
        # Correlate the lookup/subject key from the beginning of the trace with the later
        # resource result. This is how evidence logs link a user identifier to a resource.
        merged={}
        for _, tp in traces.get(trace,[]):
            for k,v in tp.items():
                if k not in merged or k in {"lookup_key","match_key","correlation_key","subject_key","subject_ref","subject_ref"}:
                    merged[k]=v
        merged.update(pairs)
        service=pairs.get("service") or merged.get("service") or infer_system(path)
        if service=="support_replica": service="support_platform"
        if service=="email_delivery_service": service="notification_service"
        event=pairs.get("event","").casefold()
        cat=infer_category(service,None,path)
        if "deletion_marker_check" in event and merged.get("source")=="legacy_contact_index": cat="SECONDARY_IDENTIFIER"
        if "attachment" in event: cat="SUPPORT_ATTACHMENT"
        elif "message" in event or "support" in service: cat="SUPPORT_MESSAGE"
        elif "profile_lookup" in event: cat="USER_PROFILE"
        elif "index_query" in event: cat="SEARCH_INDEX_ENTRY"
        elif "connector" in event or "data_flow" in rid: cat="DATA_FLOW"
        elif "restore" in event or "backup" in rid: cat="BACKUP_ARCHIVE"
        elif "audit_record" in event or "audit_record" in rid: cat="SECURITY_AUDIT_LOG"
        elif "analytics" in service or "analytics" in rid: cat="ANALYTICS_PROFILE"
        if "deletion_marker_check" in event and merged.get("source")=="legacy_contact_index": cat="SECONDARY_IDENTIFIER"
        state="PRESENT"
        if pairs.get("rows") == "0" or pairs.get("http_status") == "404" or pairs.get("result", "").casefold() in {"not_found","miss"}:
            state="ABSENT"
        if pairs.get("result", "").casefold() == "hit": state="PRESENT"
        if pairs.get("enabled", "").casefold() in {"true","1"}: state="ACTIVE"
        if pairs.get("enabled", "").casefold() in {"false","0"}: state="DISABLED"
        if pairs.get("restore_allowed", "").casefold() in {"true","1"} or pairs.get("eligible", "").casefold() == "true": state="ACTIVE"
        if pairs.get("restore_allowed", "").casefold() in {"false","0"} or pairs.get("deletion_block", "").casefold() == "true": state="BLOCKED"
        if "pii_scan" in event: state="PRESENT"
        flat={k.casefold():[v] for k,v in merged.items()}
        nullish={None,"","null","none","n/a","undefined"}
        if cat=="ANALYTICS_PROFILE" and all(str(merged.get(k,"null")).casefold() in {"null","none","n/a","undefined",""} for k in ("customer_reference","user_id","email","phone","email_hash","correlation_key","lookup_key")):
            state="ANONYMIZED"
        if cat in {"SUPPORT_MESSAGE","EMAIL_DELIVERY_LOG"} and all(str(merged.get(k,"null")).casefold() in {"null","none","n/a","undefined",""} for k in ("requester_email","customer_email","email","requester_name","requester_phone","phone","email_hash")):
            state="REDACTED"
        tm=line[:20]+'+00:00' if re.match(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',line) else file_capture
        out.append({"file_id":file_id,"captured_at":file_capture,"observed_at":parse_time(tm),"system_id":service,"resource_id":rid,"category":cat,"state":state,"record":merged,"flat":flat,"path":str(path),"source_kind":"log","raw_line":line})
    return out


def parse_text_observations(path, file_id, file_capture):
    out=[]
    text=path.read_text(encoding="utf-8-sig",errors="replace")
    # Handover rows: timestamp | system | resource | category | state | identifier
    for line in text.splitlines():
        clean=line.strip().lstrip("- ").strip()
        m=re.match(r'^\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s*\|\s*([\w]+)\s*\|\s*([\w-]+)\s*\|\s*([A-Z_]+)\s*\|\s*([A-Z_]+)\s*\|\s*(.*?)\s*$',clean)
        if m:
            tm,system,rid,cat,state,identifier=m.groups()
            flat={"identifier":[identifier]}
            if "@" in identifier: flat["email"]=[identifier]
            if re.match(r'user_\d+',identifier): flat["user_id"]=[identifier]
            out.append({"file_id":file_id,"captured_at":file_capture,"observed_at":parse_time(tm),"system_id":system,"resource_id":rid,"category":cat,"state":state,"record":{"identifier":identifier},"flat":flat,"path":str(path),"source_kind":"text"})
    # Free-form text records are handled as weak identity-bearing evidence if resource ids are explicit.
    return out


def extract_document_text(path):
    suffix=path.suffix.casefold()
    try:
        if suffix == ".pdf":
            return subprocess.check_output(["pdftotext","-layout",str(path),"-"],stderr=subprocess.DEVNULL,timeout=20).decode("utf-8",errors="replace")
        if suffix == ".png":
            return subprocess.check_output(["tesseract",str(path),"stdout"],stderr=subprocess.DEVNULL,timeout=30).decode("utf-8",errors="replace")
        return path.read_text(encoding="utf-8-sig",errors="replace")
    except Exception:
        return ""


def parse_document_observations(path, file_id, file_capture):
    if path.suffix.casefold() in {".json", ".sql", ".log", ".txt"}:
        return []
    text=extract_document_text(path)
    out=[]
    ids=re.findall(r'\b(?:account|analytics|backup|export|data_flow|search|audit_record|support|tombstone|cache|marketing|telemetry|delivery)_\d+\b',text,re.I)
    base_system=infer_system(path)
    base_cat=infer_category(base_system,None,path)
    def state_from_text(cat, txt):
        low=txt.casefold()
        if cat=="DATA_FLOW":
            if re.search(r"enabled\s*[:=]\s*(?:true|1|yes)\b",low) or re.search(r"scheduler[_ ]registered\s*[:=]\s*(?:true|1|yes)\b",low) or re.search(r"\bflow status\s*[:=]\s*active\b",low): return "ACTIVE"
            if re.search(r"enabled\s*[:=]\s*(?:false|0|no)\b",low) or re.search(r"\bflow status\s*[:=]\s*disabled\b",low): return "DISABLED"
            if "continuous" in low and "healthy" in low and "connector" in low: return "ACTIVE"
        if cat=="BACKUP_ARCHIVE":
            if re.search(r"restore[_ ]allowed\s*[:=]\s*(?:true|1|yes)\b",low) or re.search(r"restore (?:eligible|available)\s*[:=]\s*(?:true|yes)\b",low): return "ACTIVE"
            if re.search(r"restore[_ ]allowed\s*[:=]\s*(?:false|0|no)\b",low) or re.search(r"deletion[_ ]block\s*[:=]\s*(?:true|1|yes)\b",low): return "BLOCKED"
        if cat=="USER_PROFILE" and (re.search(r"\bnot[_ ]found\b",low) or re.search(r"http[_ ]status\s*[:=]\s*404\b",low) or re.search(r"profile\s*[:=]\s*null\b",low)): return "ABSENT"
        if cat=="ANALYTICS_PROFILE":
            if re.search(r"\b(anonymized|anonymised)\b",low) or all(re.search(rf"\b{k}\s*[:=]\s*(?:null|none|n/a)\b",low) for k in ("email","phone","email_hash")): return "ANONYMIZED"
        if cat=="ACCOUNT_TOMBSTONE":
            if re.search(r"\b(redacted|pii removed|identifiers removed)\b",low): return "REDACTED"
        if cat in {"SUPPORT_MESSAGE","EMAIL_DELIVERY_LOG"} and re.search(r"\b(redacted|pii removed|email removed|phone removed)\b",low): return "REDACTED"
        if re.search(r"\b(deleted|not found|absent)\b",low) and cat in DELETE_CATEGORIES: return "ABSENT"
        return "PRESENT"
    if not ids:
        out.append({"file_id":file_id,"captured_at":file_capture,"observed_at":parse_time(file_capture),"system_id":base_system,"resource_id":"","category":base_cat,"state":state_from_text(base_cat,text),"record":{"document_text":text},"flat":{"document_text":[text]},"path":str(path),"source_kind":"document_text"})
    for rid in sorted(set(ids)):
        system=expected_system_for_resource(rid) or base_system
        cat=infer_category(system,None,path)
        if rid.casefold().startswith('support_') and 'attachment' in path.name.casefold(): cat='SUPPORT_ATTACHMENT'
        out.append({"file_id":file_id,"captured_at":file_capture,"observed_at":parse_time(file_capture),"system_id":system,"resource_id":rid,"category":cat,"state":state_from_text(cat,text),"record":{"document_text":text},"flat":{"document_text":[text]},"path":str(path),"source_kind":"document"})
    return out


def activity_link_observations(activities):
    """Represent explicit data-catalog identity links as association-only observations."""
    out=[]
    email_re=re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",re.I)
    user_re=re.compile(r"\buser_\d+\b",re.I)
    for a in activities:
        if a.get("event_type")!="LINK_RESOURCE_IDENTITY": continue
        tm=parse_time(a.get("event_time")); details=a.get("details","")
        rid=a.get("resource_id")
        if not tm or not rid: continue
        email=next(iter(email_re.findall(details)),"")
        uid=next(iter(user_re.findall(details)),"")
        target=a.get("target_system") or a.get("source_system") or "unknown_service"
        flat={"resource_id":[rid],"details":[details]}
        if email: flat["email"]=[email]
        if uid: flat["user_id"]=[uid]
        cat="SUPPORT_ATTACHMENT" if target=="object_storage" and re.search(r"attachment catalog|\.pdf",details,re.I) else infer_category(target,None,"",None,{})
        out.append({"file_id":a.get("activity_id",""),"captured_at":tm,"observed_at":tm,"system_id":target,"resource_id":rid,"category":cat,"state":"LINKED","record":a,"flat":flat,"path":"system_activity.csv","source_kind":"activity_link","linked_at":tm})
    return out


def enrich_documents_from_identity_links(observations, activities):
    """Join document aliases (statement/ticket references) to explicit resource-identity links."""
    email_re=re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",re.I)
    user_re=re.compile(r"\buser_\d+\b",re.I)
    out=[]
    docs=[o for o in observations if o.get("source_kind")=="document_text" and o.get("flat",{}).get("document_text")]
    for a in activities:
        if a.get("event_type")!="LINK_RESOURCE_IDENTITY": continue
        link_time=parse_time(a.get("event_time")); details=a.get("details",""); rid=a.get("resource_id")
        if not rid or not link_time: continue
        m=re.search(r"linked\s+[^\s]+\s+\(([^)]+)\)",details,re.I)
        alias=m.group(1).strip() if m else ""
        # Only cross-link a document through a distinct business reference (statement/ticket/export
        # reference), not a bare user ID or the resource ID itself.
        aliases=[x for x in [alias] if x and x!=rid and not re.fullmatch(r"user_\d+",x,re.I)]
        if not aliases: continue
        email=next(iter(email_re.findall(details)),"")
        uid=next(iter(user_re.findall(details)),"")
        target=a.get("target_system") or a.get("source_system") or "unknown_service"
        for d in docs:
            txt=d["flat"]["document_text"][0]
            if not any(alias.casefold() in str(txt).casefold() for alias in aliases): continue
            flat=dict(d.get("flat",{}))
            if email: flat["email"]=[email]
            if uid: flat["user_id"]=[uid]
            flat["resource_id"]=[rid]
            cat="SUPPORT_ATTACHMENT" if target=="object_storage" and re.search(r"attachment catalog|\.pdf",details,re.I) else infer_category(target,None,d.get("path",""),None,{})
            out.append({"file_id":d["file_id"],"captured_at":d.get("captured_at"),"observed_at":d.get("observed_at"),"system_id":target,"resource_id":rid,"category":cat,"state":"PRESENT","record":{"document_text":txt,"linked_alias":alias,"linked_resource":rid},"flat":flat,"path":d.get("path",""),"source_kind":"document_linked","linked_at":link_time})
    return out

def load_evidence():
    manifest=read_csv(DATA/"evidence_files.csv")
    cache_path=ROOT/".audit_observations_cache.json"
    signature=[]
    for m in manifest:
        p=DATA/m["file_path"]
        if p.exists():
            st=p.stat(); signature.append((m["file_id"],m["file_path"],st.st_size,st.st_mtime_ns))
    signature.append(("parser_code",str(Path(__file__).stat().st_mtime_ns)))
    signature_hash=hashlib.sha256(json.dumps(signature,sort_keys=True).encode()).hexdigest()
    if cache_path.exists():
        try:
            cached=json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("signature")==signature_hash:
                obs=cached["observations"]
                for o in obs:
                    o["captured_at"]=parse_time(o.get("captured_at")); o["observed_at"]=parse_time(o.get("observed_at"))
                return obs,manifest
        except Exception: pass
    obs=[]
    for m in manifest:
        capture=parse_time(m.get("captured_at"))
        path=DATA/m["file_path"]
        if not path.exists(): continue
        ext=path.suffix.casefold()
        if ext==".json": rows=parse_json_observations(path,m["file_id"],capture)
        elif ext==".sql": rows=parse_sql_observations(path,m["file_id"],capture)
        elif ext==".log": rows=parse_log_observations(path,m["file_id"],capture)
        elif ext==".txt": rows=parse_text_observations(path,m["file_id"],capture)
        else: rows=parse_document_observations(path,m["file_id"],capture)
        obs.extend(rows)
    serialized=[]
    for o in obs:
        x=dict(o)
        for k in ("captured_at","observed_at"):
            if x.get(k): x[k]=x[k].isoformat()
        serialized.append(x)
    try: cache_path.write_text(json.dumps({"signature":signature_hash,"observations":serialized},ensure_ascii=False),encoding="utf-8")
    except Exception: pass
    return obs,manifest


def build_identity_maps(requests, identities, audits):
    email_to_users=defaultdict(set)
    for row in identities:
        if row.get("email"): email_to_users[norm(row["email"])].add(row["user_id"])
    for a in audits:
        if a.get("field_name","").casefold()=="email":
            for v in (a.get("old_value"),a.get("new_value")):
                if v and "@" in v: email_to_users[norm(v)].add(a["user_id"])
    # A request email is also a valid lookup key; map it through all identity/audit history.
    case_users={}
    for r in requests:
        matches=email_to_users.get(norm(r["email"]),set())
        case_users[r["case_id"]]=next(iter(matches)) if len(matches)==1 else None
    return email_to_users,case_users


def identifiers_for_case(req, uid, identities, audits):
    cutoff=parse_time(req["audit_at"])
    vals={"email":set(),"name":set(),"phone":set(),"email_hash":set(),"user_id":set()}
    vals["email"].add(norm(req.get("email")))
    if uid: vals["user_id"].add(norm(uid))
    for row in identities:
        if row.get("user_id")==uid and (not parse_time(row.get("updated_at")) or parse_time(row.get("updated_at")) <= cutoff):
            for field,key in [("email","email"),("name","name"),("phone","phone"),("email_hash","email_hash")]:
                if row.get(field): vals[key].add(norm(row[field]))
    for a in audits:
        if a.get("user_id") != uid: continue
        tm=parse_time(a.get("event_time"))
        if tm and cutoff and tm>cutoff: continue
        field=a.get("field_name","").casefold()
        key={"email":"email","name":"name","full_name":"name","phone":"phone","email_hash":"email_hash"}.get(field)
        if key:
            for v in (a.get("old_value"),a.get("new_value")):
                if v: vals[key].add(norm(v))
    # Keep only useful nonempty strings.
    return {k:{v for v in vs if v} for k,vs in vals.items()}


def observation_matches(o, identifiers):
    flat=o.get("flat",{})
    # Strong identifiers: user ids, email/hash, phone. Names are included only as full normalized values.
    for key, candidates in identifiers.items():
        aliases={key}
        if key=="email": aliases |= {"email","owner_email","customer_email","requester_email","lookup_key","match_key","correlation_key","matched_value","identifier","subject_key"}
        elif key=="email_hash": aliases |= {"email_hash","correlation_key","matched_value","lookup_key","subject_key"}
        elif key=="phone": aliases |= {"phone","owner_phone","requester_phone","customer_phone","matched_value","lookup_key","subject_key"}
        elif key=="name": aliases |= {"name","full_name","requester_name","customer_name","matched_value"}
        elif key=="user_id": aliases |= {"user_id","customer_reference","subject_reference","subject_ref","identifier","customer_reference"}
        for alias in aliases:
            for value in flat.get(alias,[]):
                if value is None: continue
                nv=norm(value)
                if key=="phone":
                    if len(norm_phone(value))>=7 and norm_phone(value) in {norm_phone(x) for x in candidates}: return True
                elif nv in candidates: return True
    # Documents and screenshots may only expose their identity in OCR-extracted text.
    for text_value in flat.get("document_text", []):
        if not text_value: continue
        text_norm=norm(text_value)
        for key,candidates in identifiers.items():
            for candidate in candidates:
                if key=="phone":
                    digits=norm_phone(candidate)
                    if len(digits)>=7 and digits in norm_phone(text_value): return True
                elif len(candidate)>=5 and candidate in text_norm: return True
    return False


def is_authorized_deletion(text):
    t=norm(text)
    # Explicit non-deletion requests override generic mention of records/account.
    negative=[r"\bdo not delete\b",r"\bdon't delete\b",r"\bdo not close\b",r"\bdon't close\b",r"\bwithout deleting\b",r"\bwithout removing any of my records\b",r"\bnot asking for deletion\b",r"\bnot request(?:ing)? deletion\b",r"\bnot a request to erase\b",r"\bnot a request to delete\b",r"\bnot asking to erase\b",r"\bkeep (?:my )?account\b"]
    if any(re.search(p,t) for p in negative): return False
    # A marketing-only opt-out is not a deletion request.
    if re.search(r"\bmarketing\b",t) and re.search(r"\b(only|just)\b",t) and not re.search(r"\b(delete|deletion|erase|erasure|remove my account|close my account|supprimer|eliminar)\b",t): return False
    # Broad multilingual deletion/erasure language.
    patterns=[r"\bdelet(?:e|ed|ing|ion|ions)\b",r"\bpermanent(?:ly)? account deletion\b",r"\berase\b",r"\berasure\b",r"\bremove (?:my |the |that |any |all )?(?:account|profile|records|record|search result|personal details)\b",r"\bclose (?:my |this |the )?account\b",r"\baccount.*closed\b",r"\baccount.*erased\b",r"\baccount.*deleted\b",r"\bdeletion as it stood\b",r"\bconfirm that my account was deleted\b",r"\bconfirm that the account was deleted\b",r"\bverify that my account was deleted\b",r"\bprofile.*removed\b",r"\baccount.*removed\b",r"\bprofile.*gone\b",r"\baccount.*gone\b",r"\bremaining records cannot identify me\b",r"\bclose the account completely\b",r"\bsuppression of personal data\b",r"\bsupprimer\b",r"\bsuppression\b",r"\beliminar\b",r"\beliminación\b",r"exclusão",r"exclusao",r"excluir",r"apagar",r"eliminação",r"eliminacao",r"削除",r"삭제",r"消去",r"删除",r"удалени",r"lösch",r"usunię",r"usunąć",r"\bborra(?:r|do)\b",r"\b löschen\b",r"\blöschen\b",r"\bentfernen\b",r"\bудалить\b",r"\b削除\b",r"\b消去\b",r"\b삭제\b",r"\busuń\b",r"\busunąć\b",r"\bcancelar mi cuenta\b"]
    return any(re.search(p,t) for p in patterns)


def category_for_observation(o):
    cat=o.get("category","UNKNOWN")
    # Logs may reveal a direct PII scan; use the service/resource context to normalize category.
    if cat=="UNKNOWN": cat=infer_category(o.get("system_id",""),None,o.get("path",""))
    return cat


def has_direct_pii(o):
    flat=o.get("flat",{})
    keys=("email","owner_email","customer_email","requester_email","phone","owner_phone","customer_phone","requester_phone","name","full_name","requester_name","email_hash","matched_value","lookup_key","match_key","correlation_key","subject_key")
    for k in keys:
        for v in flat.get(k,[]):
            if v not in (None,"") and ("@" in str(v) or len(norm_phone(v))>=7 or re.fullmatch(r"[a-f0-9]{64}",str(v).casefold()) or k in {"name","full_name","requester_name"}):
                return True
    # OCR-extracted local media may expose identifiers in free text rather than structured fields.
    for text_value in flat.get("document_text",[]):
        if not text_value: continue
        if re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",str(text_value),re.I): return True
        if re.search(r"\b[0-9a-f]{64}\b",str(text_value),re.I): return True
        if re.search(r"\+?\d[\d\s().-]{7,}\d",str(text_value)): return True
    # Explicit status labels from handover are definitive about identifiability.
    if str(o.get("state","")).upper() in {"IDENTIFIABLE","EXPOSED","PII_PRESENT"}: return True
    return False


def has_identifier_fields(o):
    flat=o.get("flat",{})
    keys=("user_id","customer_reference","subject_reference","subject_ref","email","owner_email","customer_email","requester_email","phone","owner_phone","requester_phone","name","full_name","requester_name","email_hash")
    nullish={None,"","null","none","n/a","undefined"}
    return any(any(v not in nullish and str(v).casefold() not in nullish for v in flat.get(k,[])) for k in keys)


_POLICY_ACTIONS = None

def policy_actions():
    """Load the participant-provided deletion policy once per process."""
    global _POLICY_ACTIONS
    if _POLICY_ACTIONS is None:
        _POLICY_ACTIONS = {r["data_category"].upper(): r["required_action"].upper() for r in read_csv(DATA/"deletion_rules.csv")}
    return _POLICY_ACTIONS


def category_action(cat, o):
    cat=(cat or "UNKNOWN").upper()
    action=policy_actions().get(cat)
    # Operational processes are not record categories in deletion_rules.csv, but the
    # contract explicitly requires stopping flows and blocking unsafe restores.
    if cat=="DATA_FLOW": return "DISABLE_DATA_FLOW"
    if cat=="BACKUP_ARCHIVE": return "RETAIN_BLOCK_RESTORE"
    if action=="DELETE": return "DELETE"
    if action=="REDACT": return "REDACT"
    if action=="ANONYMIZE": return "ANONYMIZE"
    if action=="RETAIN": return "RETAIN"
    return "DELETE"


def is_violation(o):
    cat=category_for_observation(o); state=str(o.get("state","")).upper()
    action=category_action(cat,o)
    if action=="DELETE": return state not in {"ABSENT","NOT_FOUND","404"} and state not in {"DELETED"}
    if action=="REDACT": return state not in {"REDACTED","ABSENT","NOT_FOUND"} and has_direct_pii(o)
    if action=="ANONYMIZE": return state not in {"ANONYMIZED","ABSENT","NOT_FOUND"} and (has_identifier_fields(o) or has_direct_pii(o))
    if action=="RETAIN_BLOCK_RESTORE": return state=="ACTIVE"
    if action=="DISABLE_DATA_FLOW": return state=="ACTIVE"
    if action=="RETAIN": return state in {"ABSENT","NOT_FOUND"}
    return False


def latest_observations(observations, identifiers, cutoff, activities=None):
    eligible=[]
    for o in observations:
        cap=o.get("captured_at")
        if cutoff and cap and cap>cutoff: continue
        if cutoff and o.get("linked_at") and o["linked_at"]>cutoff: continue
        tm=o.get("observed_at") or cap
        if cutoff and tm and tm>cutoff: continue
        eligible.append(o)
    # Resolve ownership using current and historical identifiers, then select the latest
    # evidence snapshot that is valid at audit_at for each linked resource.
    linked=set()
    for o in eligible:
        if observation_matches(o,identifiers):
            linked.add((o.get("system_id","unknown_service"),o.get("resource_id",""),category_for_observation(o)))
    by_resource=defaultdict(list)
    for o in eligible:
        key=(o.get("system_id","unknown_service"),o.get("resource_id",""),category_for_observation(o))
        if key in linked and o.get("source_kind")!="activity_link": by_resource[key].append(o)
    latest=[]
    for key, vals in by_resource.items():
        vals.sort(key=lambda o: (o.get("observed_at") or o.get("captured_at") or datetime.min.replace(tzinfo=timezone.utc),
                                 1 if o.get("source_kind") in {"text","json","document_linked"} else 0,
                                 len(o.get("flat",{}))) )
        latest.append(vals[-1])
    return latest


def sort_step_key(step, phase):
    op_orders={
        "FINDING":{"REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3},
        "REMEDIATION":{"DISABLE_DATA_FLOW":0,"BLOCK_RESTORE":1,"DELETE_RECORD":2,"REDACT_RECORD":3,"ANONYMIZE_RECORD":4},
        "VERIFICATION":{"VERIFY_RECORD_ABSENT":0,"VERIFY_RECORD_PRESENT":1,"VERIFY_RECORD_REDACTED":2,"VERIFY_RECORD_ANONYMIZED":3,"VERIFY_DATA_FLOW_DISABLED":4,"VERIFY_RESTORE_BLOCKED":5},
    }
    return (op_orders[phase].get(step["operation"],99),step["system_id"],step["resource_id"])


def mkstep(phase, system, resource, operation, state, evidence=""):
    return {"phase":phase,"system_id":str(system or "unknown_service"),"resource_id":str(resource or "unknown_resource"),"operation":operation,"state":state,"evidence_id":evidence or ""}


def add_temporal_and_referential_links(req, related, observations, activities, cutoff):
    """Use request-aligned activity timestamps to identify resources, then require evidence for state.

    Activity rows are not treated as proof of deletion success. They are only used to connect the
    request/report window to resource IDs; state comes from participant-visible evidence snapshots.
    """
    related=list(related)
    known={(o.get("system_id"),o.get("resource_id")) for o in related}
    # Follow explicit resource references found in linked records (e.g. search source_resource_id).
    referenced=set()
    for o in related:
        flat=o.get("flat",{})
        for key in ("source_resource_id","account_resource_id","parent_resource_id","linked_resource_id","origin_resource_id"):
            for v in flat.get(key,[]):
                if isinstance(v,str) and re.match(r"^(account|analytics|backup|export|data_flow|search|audit_record|support|tombstone|cache|marketing|telemetry|delivery)_\d+$",v):
                    referenced.add(v)
    for o in observations:
        if o.get("resource_id") in referenced and (not cutoff or not o.get("captured_at") or o["captured_at"]<=cutoff):
            expected=expected_system_for_resource(o.get("resource_id"))
            if expected and o.get("system_id")!=expected: continue
            tm=o.get("observed_at") or o.get("captured_at")
            if not cutoff or not tm or tm<=cutoff:
                key=(o.get("system_id"),o.get("resource_id"))
                if key not in known: related.append(o); known.add(key)
    # Match the reported workflow window to nearby operational events. This is a resource-discovery
    # heuristic, not a state assertion; every resulting resource must still have separate evidence.
    report=parse_time(req.get("reported_at"))
    if report and activities:
        candidates=[]
        allowed={"DELETE_RECORD","REDACT_RECORD","ANONYMIZE_RECORD","DISABLE_DATA_FLOW","BLOCK_RESTORE","RETAIN_RECORD","CREATE_EXPORT","INDEX_RECORD","REFRESH_CACHE","CHECK_DATA_FLOW","CHECK_RESTORE_ACCESS"}
        for a in activities:
            tm=parse_time(a.get("event_time"))
            if not tm or (cutoff and tm>cutoff) or (tm>report and (tm-report).total_seconds()>75*60) or (tm<report and (report-tm).total_seconds()>75*60):
                continue
            if a.get("event_type") not in allowed: continue
            candidates.append((abs((tm-report).total_seconds()),a))
        existing_categories={category_for_observation(o) for o in related}
        # Select at most one missing primary-account or analytics resource. Prefer resource IDs
        # that have explicit point-in-time evidence; activity alone never proves state.
        def choose_event(system, family, anchor=None):
            choices=[]
            # The workflow result is a weak association signal, not proof of state. When
            # several deletion events share a reporting window, prefer the result that
            # agrees with the request's reported workflow state before using timestamps.
            status=str(req.get("reported_status", "")).upper()
            expected_results={"COMPLETE":{"SUCCESS"},"PARTIALLY_COMPLETE":{"PARTIAL","FAILED"},"NOT_STARTED":{"FAILED"}}
            expected=expected_results.get(status,set())
            for delta,a in candidates:
                target=a.get("target_system") or a.get("source_system")
                if target!=system or a.get("event_type")!=family: continue
                rid=a.get("resource_id")
                has_evidence=any(o.get("resource_id")==rid and (not cutoff or not o.get("captured_at") or o["captured_at"]<=cutoff) for o in observations)
                tm=parse_time(a.get("event_time"))
                score=abs((tm-anchor).total_seconds()) if anchor and tm else delta
                result=str(a.get("reported_result", "")).upper()
                result_penalty=0 if expected and result in expected else (1 if expected else 0)
                choices.append((0 if has_evidence else 1,result_penalty,score,delta,a))
            return sorted(choices,key=lambda x:(x[0],x[1],x[2],x[3]))[0][4] if choices else None
        # Missing account: prefer an explicit lookup result, then use the request-aligned event
        # only as a locator for a complete replica snapshot that can prove absence.
        if "USER_PROFILE" not in existing_categories:
            a=choose_event("account_service","DELETE_RECORD")
            if a:
                rid=a.get("resource_id")
                matches=[o for o in observations if o.get("source_kind")!="activity_link" and o.get("resource_id")==rid and (not cutoff or not o.get("captured_at") or o["captured_at"]<=cutoff) and (not cutoff or not (o.get("observed_at") or o.get("captured_at")) or (o.get("observed_at") or o.get("captured_at"))<=cutoff)]
                if matches:
                    chosen=sorted(matches,key=lambda o:(o.get("observed_at") or o.get("captured_at") or datetime.min.replace(tzinfo=timezone.utc)))[-1]
                    related.append(chosen); known.add((chosen.get("system_id"),chosen.get("resource_id"))); existing_categories.add("USER_PROFILE")
                elif rid:
                    # Only the paired primary/failover snapshot supports this inference.
                    for m in read_csv(DATA/"evidence_files.csv"):
                        p=DATA/m["file_path"]; cap=parse_time(m.get("captured_at"))
                        if p.suffix.casefold()!=".sql" or not p.exists() or (cutoff and cap and cap>cutoff): continue
                        sql=p.read_text(encoding="utf-8-sig",errors="replace")
                        if "customer_profiles_primary" not in sql or "customer_profiles_failover_replica" not in sql: continue
                        if re.search(r"INSERT INTO [\"']?customer_profiles_(?:primary|failover_replica)[\"']? VALUES\s*\(\s*['\"]"+re.escape(rid)+r"['\"]",sql,re.I): continue
                        related.append({"file_id":m["file_id"],"captured_at":cap,"observed_at":cap,"system_id":"account_service","resource_id":rid,"category":"USER_PROFILE","state":"ABSENT","record":{},"flat":{},"path":str(p),"source_kind":"sql_absence"})
                        known.add(("account_service",rid)); existing_categories.add("USER_PROFILE")
                        break
        if "ANALYTICS_PROFILE" not in existing_categories:
            # If a primary deletion event is already linked, associate the nearest following
            # anonymization event to that account's workflow; otherwise use the report window.
            anchor=None
            account_ids={o.get("resource_id") for o in related if category_for_observation(o)=="USER_PROFILE"}
            for a in activities:
                if a.get("resource_id") in account_ids and a.get("event_type")=="DELETE_RECORD":
                    tm=parse_time(a.get("event_time"))
                    if tm and (anchor is None or abs((tm-report).total_seconds())<abs((anchor-report).total_seconds())): anchor=tm
            a=choose_event("analytics_platform","ANONYMIZE_RECORD",anchor)
            if a:
                rid=a.get("resource_id")
                matches=[o for o in observations if o.get("source_kind")!="activity_link" and o.get("resource_id")==rid and (not cutoff or not o.get("captured_at") or o["captured_at"]<=cutoff) and (not cutoff or not (o.get("observed_at") or o.get("captured_at")) or (o.get("observed_at") or o.get("captured_at"))<=cutoff)]
                if matches:
                    chosen=sorted(matches,key=lambda o:(o.get("observed_at") or o.get("captured_at") or datetime.min.replace(tzinfo=timezone.utc)))[-1]
                    related.append(chosen); known.add((chosen.get("system_id"),chosen.get("resource_id"))); existing_categories.add("ANALYTICS_PROFILE")
    # If an account record was observed elsewhere but the same ID has a later snapshot absence,
    # latest_observations normally picks it. Return all candidates; caller deduplicates.
    return related

def add_identity_link_risks(req, related, observations, identifiers, cutoff, findings, remediation, verification):
    """Fail closed on explicit identity-to-resource links when no record state was found."""
    # Catalog links are a fallback for resources without state evidence. Avoid adding a second
    # same-category copy when a directly evidenced copy already exists, except for flows/backups
    # and anonymized records where the unresolved link itself is a material risk.
    links=[]
    for o in observations:
        if o.get("source_kind")!="activity_link": continue
        tm=o.get("linked_at") or o.get("captured_at")
        if cutoff and tm and tm>cutoff: continue
        if observation_matches(o,identifiers): links.append(o)
    for link in links:
        cat=category_for_observation(link); sysid=link.get("system_id","unknown_service"); rid=link.get("resource_id","")
        if not rid or cat in RETAIN_CATEGORIES or cat=="ACCOUNT_TOMBSTONE" or cat=="SECURITY_AUDIT_LOG": continue
        same=[o for o in related if o.get("resource_id")==rid and (o.get("system_id")==sysid or expected_system_for_resource(rid)==o.get("system_id"))]
        # Avoid unrelated link-only copies of a category already represented by direct evidence.
        other_same_category=any(category_for_observation(o)==cat and o.get("resource_id")!=rid for o in related)
        if not same and other_same_category and cat not in {"DATA_FLOW","BACKUP_ARCHIVE"}: continue
        # If a state-backed finding already exists for this resource, do not duplicate it.
        if any(s.get("resource_id")==rid and s.get("system_id")==sysid for s in findings): continue
        state= str(same[-1].get("state","")).upper() if same else "UNKNOWN"
        if cat in DELETE_CATEGORIES:
            if state in {"ABSENT","NOT_FOUND","404"}: continue
            op="REPORT_REMAINING_RECORD"; action="DELETE_RECORD"; verify="VERIFY_RECORD_ABSENT"; rem_state="ABSENT"; ver_state="ABSENT"
        elif cat in REDACT_CATEGORIES:
            # A separate catalog link can still make an otherwise-redacted record identifiable.
            if cat=="ACCOUNT_TOMBSTONE": continue
            op="REPORT_EXPOSED_PII"; action="REDACT_RECORD"; verify="VERIFY_RECORD_REDACTED"; rem_state="REDACTED"; ver_state="REDACTED"
        elif cat in ANON_CATEGORIES:
            # A resource-to-user mapping defeats anonymization even if the record fields are null.
            op="REPORT_EXPOSED_PII"; action="ANONYMIZE_RECORD"; verify="VERIFY_RECORD_ANONYMIZED"; rem_state="ANONYMIZED"; ver_state="ANONYMIZED"
        elif cat=="DATA_FLOW":
            if state=="DISABLED": continue
            op="REPORT_ACTIVE_DATA_FLOW"; action="DISABLE_DATA_FLOW"; verify="VERIFY_DATA_FLOW_DISABLED"; rem_state="DISABLED"; ver_state="DISABLED"
        elif cat=="BACKUP_ARCHIVE":
            if state=="BLOCKED": continue
            op="REPORT_RESTORE_RISK"; action="BLOCK_RESTORE"; verify="VERIFY_RESTORE_BLOCKED"; rem_state="BLOCKED"; ver_state="BLOCKED"
        else:
            continue
        evidence=link.get("file_id","")
        findings.append(mkstep("FINDING",sysid,rid,op,"ACTIVE" if op in {"REPORT_ACTIVE_DATA_FLOW","REPORT_RESTORE_RISK"} else "PRESENT",evidence))
        remediation.append(mkstep("REMEDIATION",sysid,rid,action,rem_state,""))
        verification.append(mkstep("VERIFICATION",sysid,rid,verify,ver_state,""))

def add_activity_risk_plan(req, related, activities, cutoff, identifiers, findings, remediation, verification):
    """When record snapshots are missing, preserve explicit unresolved operational risks.

    This fallback only uses activity rows whose details explicitly describe a failed/partial
    mutation, an enabled connector, or a restorable backup. It never treats a SUCCESS deletion
    result as proof of absence.
    """
    if not activities: return
    report=parse_time(req.get("reported_at"))
    if not report: return
    account_absent=any(category_for_observation(o)=="USER_PROFILE" and str(o.get("state","")).upper() in {"ABSENT","NOT_FOUND","404"} for o in related)
    if findings or account_absent: return
    candidates=[]
    # Never attach an unrelated operational event to a person solely because it happened
    # near the workflow timestamp. The event must name one of this person's resolved
    # identifiers or refer to a resource already linked by evidence.
    linked_resources={str(o.get("resource_id")) for o in related if o.get("resource_id")}
    resolved_values=set()
    for values in (identifiers or {}).values():
        resolved_values.update(norm(v) for v in values if v)
    for a in activities:
        tm=parse_time(a.get("event_time"))
        if not tm or (cutoff and tm>cutoff): continue
        if abs((tm-report).total_seconds())>75*60: continue
        et=a.get("event_type",""); result=str(a.get("reported_result","")).upper(); details=str(a.get("details", ""))
        operation=None; state=None; phase_op=None; remediation_op=None; verification_op=None
        target=a.get("target_system") or a.get("source_system") or "unknown_service"
        rid=a.get("resource_id")
        if not rid: continue
        details_norm=norm(details)
        explicitly_linked=(rid in linked_resources) or any(len(v)>=5 and v in details_norm for v in resolved_values)
        if not explicitly_linked: continue
        if et=="CHECK_DATA_FLOW" and re.search(r"remains enabled|still enabled|connector.*enabled",details,re.I):
            operation="REPORT_ACTIVE_DATA_FLOW"; state="ACTIVE"; remediation_op="DISABLE_DATA_FLOW"; verification_op="VERIFY_DATA_FLOW_DISABLED"
        elif et=="CHECK_RESTORE_ACCESS" and re.search(r"can still be restored|remains restorable|restore.*eligible",details,re.I):
            operation="REPORT_RESTORE_RISK"; state="ACTIVE"; remediation_op="BLOCK_RESTORE"; verification_op="VERIFY_RESTORE_BLOCKED"
        elif et=="SYNC_RECORD" and rid.startswith("data_flow_") and re.search(r"active connector repopulated|connector repopulated",details,re.I):
            operation="REPORT_ACTIVE_DATA_FLOW"; state="ACTIVE"; target="integration_service"; remediation_op="DISABLE_DATA_FLOW"; verification_op="VERIFY_DATA_FLOW_DISABLED"
        elif et=="DELETE_RECORD" and result in {"FAILED","PARTIAL"}:
            operation="REPORT_REMAINING_RECORD"; state="PRESENT"; remediation_op="DELETE_RECORD"; verification_op="VERIFY_RECORD_ABSENT"
        elif et in {"REDACT_RECORD","ANONYMIZE_RECORD"} and result in {"FAILED","PARTIAL"}:
            operation="REPORT_EXPOSED_PII"; state="PRESENT"
            if et=="ANONYMIZE_RECORD" or target=="analytics_platform": remediation_op="ANONYMIZE_RECORD"; verification_op="VERIFY_RECORD_ANONYMIZED"
            else: remediation_op="REDACT_RECORD"; verification_op="VERIFY_RECORD_REDACTED"
        if not operation: continue
        # Avoid duplicate reports for resources already covered by direct record findings.
        if any(s.get("resource_id")==rid for s in findings): continue
        candidates.append((abs((tm-report).total_seconds()),tm,a,target,rid,operation,state,remediation_op,verification_op))
    # Keep the nearest actionable event per resource, preserving independent risks across systems.
    seen=set()
    for _,tm,a,target,rid,operation,state,remediation_op,verification_op in sorted(candidates,key=lambda x:(x[0],x[1])):
        if (target,rid) in seen: continue
        seen.add((target,rid))
        evidence=a.get("activity_id","")
        findings.append(mkstep("FINDING",target,rid,operation,state,evidence))
        remediation.append(mkstep("REMEDIATION",target,rid,remediation_op,"DISABLED" if remediation_op=="DISABLE_DATA_FLOW" else ("BLOCKED" if remediation_op=="BLOCK_RESTORE" else ("ABSENT" if remediation_op=="DELETE_RECORD" else ("ANONYMIZED" if remediation_op=="ANONYMIZE_RECORD" else "REDACTED"))),""))
        verification.append(mkstep("VERIFICATION",target,rid,verification_op,"DISABLED" if verification_op=="VERIFY_DATA_FLOW_DISABLED" else ("BLOCKED" if verification_op=="VERIFY_RESTORE_BLOCKED" else ("ABSENT" if verification_op=="VERIFY_RECORD_ABSENT" else ("ANONYMIZED" if verification_op=="VERIFY_RECORD_ANONYMIZED" else "REDACTED"))),""))

def steps_for_case(req, observations, identities, audits, uid, activities=None):
    if not is_authorized_deletion(req.get("request_text","")):
        return "NOT_APPLICABLE", []
    cutoff=parse_time(req["audit_at"])
    ids=identifiers_for_case(req,uid,identities,audits)
    related=latest_observations(observations,ids,cutoff,activities or [])
    related=add_temporal_and_referential_links(req,related,observations,activities or [],cutoff)
    # Re-select the latest state after adding linked resource candidates, while retaining inferred snapshot absences.
    merged_by_key={}
    for o in related:
        key=(o.get("system_id"),o.get("resource_id"),category_for_observation(o))
        old=merged_by_key.get(key)
        tm=o.get("observed_at") or o.get("captured_at") or datetime.min.replace(tzinfo=timezone.utc)
        oldtm=(old.get("observed_at") or old.get("captured_at") or datetime.min.replace(tzinfo=timezone.utc)) if old else None
        if old is None or tm>=oldtm: merged_by_key[key]=o
    related=list(merged_by_key.values())
    # Keep resource records with an actual direct link. If a broad free-form document matches only by a name/email
    # but lacks a specific resource, do not fabricate a resource-level finding.
    related=[o for o in related if o.get("resource_id") and not o.get("resource_id"," ").startswith("None")]
    findings=[]; remediation=[]; verification=[]
    violated=[]
    for o in related:
        cat=category_for_observation(o); action=category_action(cat,o); state=str(o.get("state","")).upper()
        sysid=o.get("system_id") or category_to_system(cat)
        rid=o.get("resource_id")
        evidence=o.get("file_id","")
        if action=="DELETE" and state not in {"ABSENT","NOT_FOUND","404","DELETED"}:
            findings.append(mkstep("FINDING",sysid,rid,"REPORT_REMAINING_RECORD","PRESENT",evidence)); violated.append((o,action))
            remediation.append(mkstep("REMEDIATION",sysid,rid,"DELETE_RECORD","ABSENT",""))
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RECORD_ABSENT","ABSENT",""))
        elif action=="REDACT" and state not in {"REDACTED","ABSENT","NOT_FOUND"} and has_direct_pii(o):
            findings.append(mkstep("FINDING",sysid,rid,"REPORT_EXPOSED_PII","PRESENT",evidence)); violated.append((o,action))
            remediation.append(mkstep("REMEDIATION",sysid,rid,"REDACT_RECORD","REDACTED",""))
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RECORD_REDACTED","REDACTED",""))
        elif action=="ANONYMIZE" and state not in {"ANONYMIZED","ABSENT","NOT_FOUND"} and (has_identifier_fields(o) or has_direct_pii(o)):
            findings.append(mkstep("FINDING",sysid,rid,"REPORT_EXPOSED_PII","PRESENT",evidence)); violated.append((o,action))
            remediation.append(mkstep("REMEDIATION",sysid,rid,"ANONYMIZE_RECORD","ANONYMIZED",""))
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED",""))
        elif action=="DISABLE_DATA_FLOW" and state=="ACTIVE":
            findings.append(mkstep("FINDING",sysid,rid,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",evidence)); violated.append((o,action))
            remediation.append(mkstep("REMEDIATION",sysid,rid,"DISABLE_DATA_FLOW","DISABLED",""))
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_DATA_FLOW_DISABLED","DISABLED",""))
        elif action=="RETAIN_BLOCK_RESTORE" and state=="ACTIVE":
            findings.append(mkstep("FINDING",sysid,rid,"REPORT_RESTORE_RISK","ACTIVE",evidence)); violated.append((o,action))
            remediation.append(mkstep("REMEDIATION",sysid,rid,"BLOCK_RESTORE","BLOCKED",""))
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RESTORE_BLOCKED","BLOCKED",""))
        elif action=="RETAIN" and state not in {"ABSENT","NOT_FOUND"}:
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RECORD_PRESENT","PRESENT",evidence))
        elif cat=="ACCOUNT_TOMBSTONE" and state=="REDACTED":
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RECORD_REDACTED","REDACTED",evidence))
        elif cat in ANON_CATEGORIES and state=="ANONYMIZED":
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED",evidence))
        elif cat in REDACT_CATEGORIES and state=="REDACTED":
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RECORD_REDACTED","REDACTED",evidence))
        elif action=="RETAIN_BLOCK_RESTORE" and state=="BLOCKED":
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_RESTORE_BLOCKED","BLOCKED",evidence))
        elif action=="DISABLE_DATA_FLOW" and state=="DISABLED":
            verification.append(mkstep("VERIFICATION",sysid,rid,"VERIFY_DATA_FLOW_DISABLED","DISABLED",evidence))
    # Explicit data-catalog identity links can expose or locate resources even when the target
    # snapshot is missing; use them conservatively, without treating them as proof of compliance.
    add_identity_link_risks(req,related,observations,ids,cutoff,findings,remediation,verification)
    # If no direct record finding exists and account absence is not proven, retain explicit
    # unresolved risks from nearby operational checks/failures instead of emitting an empty plan.
    add_activity_risk_plan(req,related,activities or [],cutoff,ids,findings,remediation,verification)
    # Ensure account deletion is verified whenever a resource-level account observation exists.
    account_obs=[o for o in related if category_for_observation(o)=="USER_PROFILE"]
    if account_obs:
        a=max(account_obs,key=lambda o:(o.get("observed_at") or o.get("captured_at") or datetime.min.replace(tzinfo=timezone.utc)))
        if str(a.get("state","")).upper() in {"ABSENT","NOT_FOUND","404"}:
            if not any(s["operation"]=="VERIFY_RECORD_ABSENT" and s["system_id"]==a["system_id"] and s["resource_id"]==a["resource_id"] for s in verification):
                verification.append(mkstep("VERIFICATION",a["system_id"],a["resource_id"],"VERIFY_RECORD_ABSENT","ABSENT",a.get("file_id","")))
        elif not any(s["operation"]=="REPORT_REMAINING_RECORD" and s["resource_id"]==a["resource_id"] for s in findings):
            # A present primary profile is already a deletion violation above.
            pass
    # Remove duplicate steps by semantic identity, preserving the strongest evidence if duplicates occur.
    def dedupe(steps):
        result={}
        for s in steps:
            k=(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"])
            if k not in result or (not result[k]["evidence_id"] and s["evidence_id"]): result[k]=s
        return list(result.values())
    findings=sorted(dedupe(findings),key=lambda s:sort_step_key(s,"FINDING"))
    remediation=sorted(dedupe(remediation),key=lambda s:sort_step_key(s,"REMEDIATION"))
    verification=sorted(dedupe(verification),key=lambda s:sort_step_key(s,"VERIFICATION"))
    if findings:
        # An incomplete case needs a complete post-remediation verification plan. Future checks must have empty evidence.
        future=[]
        for s in verification:
            s=dict(s); s["evidence_id"]=""; future.append(s)
        steps=findings+remediation+future
        status="INCOMPLETE"
    else:
        # Complete is only defensible when an account lookup positively proves absence and no unresolved flow/restore exists.
        account_absent=any(category_for_observation(o)=="USER_PROFILE" and str(o.get("state","")).upper() in {"ABSENT","NOT_FOUND","404"} for o in related)
        unresolved=any(category_action(category_for_observation(o),o) in {"DISABLE_DATA_FLOW","RETAIN_BLOCK_RESTORE"} and str(o.get("state","")).upper()=="ACTIVE" for o in related)
        if account_absent and not unresolved:
            status="COMPLETE"
            # Complete cases cite evidence for all verification steps.
            steps=[s for s in verification if s.get("evidence_id")]
            # Account absent must be present in the verification set.
            if not any(s["operation"]=="VERIFY_RECORD_ABSENT" and s["system_id"]==o["system_id"] and s["resource_id"]==o["resource_id"] for s in steps for o in related if category_for_observation(o)=="USER_PROFILE" and str(o.get("state","")).upper() in {"ABSENT","NOT_FOUND","404"}):
                ao=next(o for o in related if category_for_observation(o)=="USER_PROFILE" and str(o.get("state","")).upper() in {"ABSENT","NOT_FOUND","404"})
                steps.append(mkstep("VERIFICATION",ao["system_id"],ao["resource_id"],"VERIFY_RECORD_ABSENT","ABSENT",ao.get("file_id","")))
            steps=sorted(dedupe(steps),key=lambda s:sort_step_key(s,"VERIFICATION"))
        else:
            status="INCOMPLETE"
            # If evidence is insufficient to prove deletion, do not claim complete. Keep findings from known risks if any.
            steps=findings+remediation+[{**s,"evidence_id":""} for s in verification]
    for i,s in enumerate(steps,1): s["step_no"]=i
    # Contract requires exact field set and phase order. Rebuild exact keys in output order.
    steps=[{"step_no":s["step_no"],"phase":s["phase"],"system_id":s["system_id"],"resource_id":s["resource_id"],"operation":s["operation"],"state":s["state"],"evidence_id":s["evidence_id"]} for s in steps]
    return status,steps


def validate_output(path, requests):
    with open(path,encoding="utf-8-sig",newline="") as f: rows=list(csv.DictReader(f))
    assert rows and list(rows[0].keys())==["case_id","deletion_status","steps_json"], "wrong header"
    assert len(rows)==len(requests), f"expected {len(requests)} rows, got {len(rows)}"
    assert [r["case_id"] for r in rows]==sorted(r["case_id"] for r in rows), "rows not sorted by case_id"
    valid_ops={"REPORT_REMAINING_RECORD","REPORT_EXPOSED_PII","REPORT_ACTIVE_DATA_FLOW","REPORT_RESTORE_RISK","DISABLE_DATA_FLOW","BLOCK_RESTORE","DELETE_RECORD","REDACT_RECORD","ANONYMIZE_RECORD","VERIFY_RECORD_ABSENT","VERIFY_RECORD_PRESENT","VERIFY_RECORD_REDACTED","VERIFY_RECORD_ANONYMIZED","VERIFY_DATA_FLOW_DISABLED","VERIFY_RESTORE_BLOCKED"}
    valid_evidence={r["file_id"] for r in read_csv(DATA/"evidence_files.csv")}
    valid_evidence|={r["activity_id"] for r in read_csv(DATA/"system_activity.csv")}
    valid_evidence|={r["audit_id"] for r in read_csv(DATA/"user_audit_log.csv")}
    phase_order={"FINDING":0,"REMEDIATION":1,"VERIFICATION":2}
    for row in rows:
        assert row["deletion_status"] in {"COMPLETE","INCOMPLETE","NOT_APPLICABLE"}
        steps=json.loads(row["steps_json"])
        if row["deletion_status"]=="NOT_APPLICABLE": assert steps==[]
        assert [s["step_no"] for s in steps]==list(range(1,len(steps)+1)), f"bad step numbering: {row['case_id']}"
        phases=[phase_order[s["phase"]] for s in steps]
        assert phases==sorted(phases), f"phase order violation: {row['case_id']}"
        for phase in ("FINDING","REMEDIATION","VERIFICATION"):
            phase_steps=[s for s in steps if s["phase"]==phase]
            assert phase_steps==sorted(phase_steps,key=lambda s:sort_step_key(s,phase)), f"operation/system/resource ordering violation: {row['case_id']} {phase}"
        for s in steps:
            assert s["phase"] in phase_order
            assert s["operation"] in valid_ops
            assert set(s)=={"step_no","phase","system_id","resource_id","operation","state","evidence_id"}
            if s["evidence_id"]: assert s["evidence_id"] in valid_evidence, f"unknown evidence ID {s['evidence_id']}"
            if s["phase"]=="FINDING": assert s["evidence_id"], f"finding missing evidence: {row['case_id']}"
            if row["deletion_status"]=="COMPLETE":
                assert s["phase"]=="VERIFICATION" and s["evidence_id"]
            if row["deletion_status"]=="INCOMPLETE" and s["phase"] in {"REMEDIATION","VERIFICATION"}:
                assert s["evidence_id"]==""
    return rows


def main():
    requests=read_csv(DATA/"deletion_requests.csv")
    identities=read_csv(DATA/"user_identities.csv")
    audits=read_csv(DATA/"user_audit_log.csv")
    activities=read_csv(DATA/"system_activity.csv")
    observations,manifest=load_evidence()
    observations.extend(activity_link_observations(activities))
    observations.extend(enrich_documents_from_identity_links(observations,activities))
    email_map,case_users=build_identity_maps(requests,identities,audits)
    out_rows=[]
    for req in requests:
        uid=case_users.get(req["case_id"])
        status,steps=steps_for_case(req,observations,identities,audits,uid,activities)
        out_rows.append({"case_id":req["case_id"],"deletion_status":status,"steps_json":json.dumps(steps,ensure_ascii=False,separators=(",",":"))})
    out_rows.sort(key=lambda r:r["case_id"])
    with open(OUT,"w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"],lineterminator="\n")
        w.writeheader(); w.writerows(out_rows)
    validate_output(OUT,requests)
    from collections import Counter
    print(f"Wrote {len(out_rows)} rows to {OUT}")
    print("Statuses:",dict(Counter(r["deletion_status"] for r in out_rows)))
    print(f"Parsed {len(observations)} observations from {len(manifest)} evidence files")

if __name__=="__main__": main()
