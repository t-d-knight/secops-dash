#!/usr/bin/env python3
"""
In-process mock of every vendor API the collectors call, shaped on the
documented responses, with multi-page pagination on each so paging logic is
actually exercised. Used by tests/run_e2e.py -- never by production code.
"""
import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

NOW = dt.datetime.now(dt.timezone.utc)


def iso(days_ago=0, hours_ago=0):
    return (NOW - dt.timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


HOSTS = {
    "aid1": {"device_id": "aid1", "hostname": "RVH-WS01", "groups": ["g1"], "tags": [], "machine_domain": "corp",
             "ou": ["Workstations"], "local_ip": "10.1.2.3", "platform_name": "Windows", "os_version": "Windows 11",
             "product_type_desc": "Workstation", "last_seen": iso(0, 2), "first_seen": iso(300),
             "agent_version": "7.20", "reduced_functionality_mode": "no", "status": "normal",
             "mac_address": "00-50-56-aa-bb-01", "device_policies": {"prevention": {"policy_id": "p1"}}},
    "aid2": {"device_id": "aid2", "hostname": "LKH-SRV01", "groups": [], "tags": ["SensorGroupingTags/LKH"],
             "local_ip": "10.9.0.4", "platform_name": "Windows", "product_type_desc": "Server",
             "last_seen": iso(2), "first_seen": iso(400), "reduced_functionality_mode": "no"},
    "aid3": {"device_id": "aid3", "hostname": "RANDOM01", "groups": [], "tags": [], "machine_domain": "rvh.local",
             "product_type_desc": "Workstation", "last_seen": iso(20), "first_seen": iso(500),
             "reduced_functionality_mode": "yes"},
    "aid4": {"device_id": "aid4", "hostname": "MYSTERY", "groups": [], "tags": [],
             "product_type_desc": "Domain Controller", "last_seen": iso(1), "first_seen": iso(100)},
}


def _vuln(vid, aid, cve, sev, score, status, *, vector=None, exploit=0, app=("google", "chrome", "Chrome 120"),
          rem=None, created=30, updated=1, closed=None, suppressed=False, kev=False):
    h = HOSTS[aid]
    return {
        "id": vid, "aid": aid, "status": status, "vulnerability_id": cve,
        "created_timestamp": iso(created), "updated_timestamp": iso(updated),
        "closed_timestamp": iso(closed) if closed is not None else None,
        "cve": {"id": cve, "base_score": score, "severity": sev, "vector": vector, "exploit_status": exploit,
                "exprt_rating": "HIGH", "types": ["Vulnerability"], "description": f"{cve} desc",
                "is_cisa_kev": kev, "remediation_level": "O"},
        "apps": [{"vendor_normalized": app[0], "product_name_normalized": app[1], "product_name_version": app[2]}],
        "remediation": {"ids": [rem[0]] if rem else [],
                        "entities": [{"id": rem[0], "title": rem[1], "action": rem[1]}] if rem else []},
        "host_info": {"hostname": h["hostname"], "groups": [{"id": g, "name": "RVH Workstations"} for g in h.get("groups", [])],
                      "tags": h.get("tags", []), "machine_domain": h.get("machine_domain"),
                      "product_type_desc": h.get("product_type_desc"), "internet_exposure": "No"},
        "suppression_info": {"is_suppressed": suppressed},
    }


OPEN_VULNS = [
    _vuln("v1", "aid1", "CVE-2024-0001", "CRITICAL", 9.8, "open", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          exploit=90, rem=("R1", "Update Google Chrome to 131"), updated=10),
    _vuln("v2", "aid1", "CVE-2024-0002", "HIGH", 8.1, "reopen", rem=("R1", "Update Google Chrome to 131")),
    _vuln("v3", "aid2", "CVE-2023-9999", "MEDIUM", 5.0, "open", suppressed=True),
    _vuln("v4", "aid4", "CVE-2021-44228", "CRITICAL", 10.0, "open", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          exploit=90, app=("apache", "log4j", "log4j 2.14"), rem=("R2", "Update Apache Log4j"), kev=True),
]
CLOSED_VULNS = [
    _vuln("v5", "aid2", "CVE-2022-1111", "HIGH", 7.5, "closed", created=20, updated=3, closed=3),
]

IDENTITY_PAGES = [
    {"nodes": [
        {"entityId": "e1", "primaryDisplayName": "Svc Backup", "secondaryDisplayName": "svc_backup@rvh.local",
         "type": "USER", "riskScore": 0.81, "riskScoreSeverity": "HIGH",
         "riskFactors": [{"type": "STALE_ACCOUNT", "severity": "MEDIUM"}, {"type": "WEAK_PASSWORD", "severity": "HIGH"}],
         "accounts": [{"domain": "RVH.LOCAL", "samAccountName": "svc_backup", "ou": "rvh.local/Service Accounts",
                       "enabled": True, "creationTime": iso(2000), "passwordAttributes": {"lastChange": iso(900)}}]},
    ], "pageInfo": {"hasNextPage": True, "endCursor": "c1"}},
    {"nodes": [
        {"entityId": "e2", "primaryDisplayName": "Jo Nurse", "secondaryDisplayName": "jo@lakesidehealth.test",
         "type": "USER", "riskScore": 0.4, "riskScoreSeverity": "MEDIUM",
         "riskFactors": [{"type": "PASSWORD_NEVER_EXPIRES", "severity": "LOW"}],
         "accounts": [{"domain": "LKH.LOCAL", "samAccountName": "jnurse", "ou": "OU=Lakeside,DC=lkh,DC=local",
                       "enabled": True}]},
        {"entityId": "e3", "primaryDisplayName": "Who Knows", "secondaryDisplayName": None, "type": "USER",
         "riskScore": 0.1, "riskScoreSeverity": "LOW", "riskFactors": [], "accounts": []},
    ], "pageInfo": {"hasNextPage": False, "endCursor": None}},
]

def _tag(name):
    return [{"tagId": f"t-{name}", "name": name, "tagAssignmentMethod": "Manual"}]


HADRIAN_ASSETS = [
    {"assetId": "a1", "value": "portal.riversidehealth.test", "platformAssetType": "Domain",
     "detectedOnUtc": iso(90), "lastSeenAtUtc": iso(0), "tags": _tag("RVH"),
     "services": [{"assetId": "svc1", "value": "portal.riversidehealth.test:443", "port": 443,
                   "ipAsset": {"assetId": "ip1", "value": "203.0.113.5"}}]},
    {"assetId": "a2", "value": "vpn.lakesidehealth.test", "platformAssetType": "Domain",
     "detectedOnUtc": iso(60), "lastSeenAtUtc": iso(0), "tags": [],   # untagged: site from apex domain
     "services": [{"assetId": "svc2", "value": "vpn.lakesidehealth.test:443", "port": 443,
                   "ipAsset": {"assetId": "ip2", "value": "198.51.100.7"}},
                  {"assetId": "svc3", "value": "vpn.lakesidehealth.test:10443", "port": 10443,
                   "ipAsset": {"assetId": "ip2", "value": "198.51.100.7"}}]},
    {"assetId": "a3", "value": "old.riversidehealth.test", "platformAssetType": "Domain",
     "detectedOnUtc": iso(400), "lastSeenAtUtc": iso(200), "tags": _tag("zzArchive")},   # archived: skipped
]
HADRIAN_RISKS = [
    {"id": "r1", "title": "Unpatched Apache Log4j - Actively Exploited", "riskSeverity": "Critical",
     "activityStatus": "Open", "status": "New", "riskType": "UnpatchedTechnology", "riskVisibility": "Visible",
     "primaryCategory": {"id": "unpatched-technology"}, "created": iso(5), "lastSeen": iso(0), "resolvedOn": None},
    {"id": "r2", "title": "Expired TLS certificate", "riskSeverity": "Medium", "activityStatus": "Closed",
     "status": "NotFound", "riskType": "Potential", "riskVisibility": "Visible", "primaryCategory": {"id": "tls-ssl"},
     "created": iso(40), "lastSeen": iso(2), "resolvedOn": iso(2)},
    {"id": "r3", "title": "Infostealer Infection: someone@riversidehealth.test compromised", "riskSeverity": "Low",
     "activityStatus": "Open", "status": "Reopened", "riskType": "InfectedDevice", "riskVisibility": "Visible",
     "primaryCategory": {"id": "leaked-credentials"}, "created": iso(12), "lastSeen": iso(0), "resolvedOn": None},
    {"id": "r4", "title": "Missing DMARC record", "riskSeverity": "Low", "activityStatus": "Open", "status": "New",
     "riskType": "Potential", "riskVisibility": "Visible", "primaryCategory": {"id": "email-security"},
     "created": iso(3), "lastSeen": iso(0), "resolvedOn": None},   # only on the archived asset: skipped
]
# GET /risks/{id}: the list has no asset link, the detail's relatedAssets does
HADRIAN_RISK_ASSET = {"r1": "a1", "r2": "a2", "r3": "a1", "r4": "a3"}

AD = ["Active Directory"]
PASSIVE = ["Falcon passive discovery"]
DISCOVER = [   # Discover "unmanaged" records, one per classify_unmanaged() class worth testing
    {"id": "u1", "hostname": None, "entity_type": "unmanaged", "current_local_ip": "10.1.5.5", "platform_name": "Linux",
     "data_providers": PASSIVE, "mac_addresses": ["a4:bb:6d:00:00:01"], "system_manufacturer": "Dell Inc.",
     "last_seen_timestamp": iso(1), "first_seen_timestamp": iso(10)},                                # network_device, site via CIDR
    {"id": "u2", "hostname": "RVH-WS99$", "entity_type": "unmanaged", "data_providers": AD, "machine_domain": "rvh.local",
     "ous": ["Workstations"], "os_version": "Windows 11", "ad_user_account_control": 4096, "account_enabled": "Yes",
     "creation_timestamp": iso(200), "last_seen_timestamp": iso(1), "descriptions": ["Dell Latitude"]},  # workstation_no_sensor
    {"id": "u3", "hostname": "RVHSQL_GMSA$", "entity_type": "unmanaged", "data_providers": AD,
     "machine_domain": "rvh.local", "ad_user_account_control": 4096, "account_enabled": "Yes",
     "last_seen_timestamp": iso(1)},                                                                  # service_account
    {"id": "u4", "hostname": "RVH-WS01$", "entity_type": "unmanaged", "data_providers": AD, "machine_domain": "rvh.local",
     "os_version": "Windows 11", "ad_user_account_control": 4096, "account_enabled": "Yes",
     "last_seen_timestamp": iso(0)},                                                                  # duplicate_of_managed (aid1)
    {"id": "u5", "hostname": None, "entity_type": "unmanaged", "data_providers": PASSIVE, "current_local_ip": "172.16.9.9",
     "mac_addresses": ["00:50:56:99:00:01"], "system_manufacturer": "VMware, Inc.", "discoverer_aids": ["aid2"],
     "last_seen_timestamp": iso(0)},                                                                  # vmware_nic, site via discoverer
    {"id": "u6", "hostname": "RVHAPP02$", "entity_type": "unmanaged", "data_providers": AD, "machine_domain": "rvh.local",
     "ous": ["Departed Service", "Servers"], "os_version": "Windows Server 2019", "ad_user_account_control": 4096,
     "account_enabled": "Yes", "last_seen_timestamp": iso(2)},                                        # out_of_scope
    {"id": "u7", "hostname": None, "entity_type": "unmanaged", "data_providers": PASSIVE, "current_local_ip": "10.1.9.9",
     "mac_addresses": ["00:50:56:AA:BB:01"], "system_manufacturer": "VMware, Inc.",
     "last_seen_timestamp": iso(0)},                                                                  # secondary_ip_of_managed (aid1's MAC)
]

HEC_PAGES = [
    [{"eventId": "h1", "type": "phishing", "severity": "4", "state": "remediated", "saas": "office365_emails",
      "eventCreated": iso(1), "senderAddress": "evil@bad.example",
      "description": "Phishing email sent from evil@bad.example to nurse@riversidehealth.test was quarantined",
      "actions": [{"actionType": "quarantine"}], "entityLink": "https://portal/e/h1"}],
    [{"eventId": "h2", "type": "malware", "severity": "5", "state": "detected", "saas": "office365_emails",
      "eventCreated": iso(0, 3), "senderAddress": "x@spam.example",
      "data": {"recipients": ["ward@lakesidehealth.test"]}, "actions": []}],
    [{"eventId": "h3", "type": "dlp", "severity": "3", "state": "detected", "saas": "office365_emails",
      "eventCreated": iso(0, 1), "senderAddress": "clerk@riversidehealth.test",
      "description": "Outbound DLP match: clerk@riversidehealth.test sent a file with sensitive customer "
                      "records to personal@gmail.com",
      "actions": [], "entityLink": "https://portal/e/h3"}],
]

DMARC_HITS = [
    {"date_begin": iso(1), "header_from": "riversidehealth.test", "source_ip_address": "40.107.1.1",
     "source_base_domain": "outlook.com", "source_name": "Microsoft", "message_count": 1000,
     "passed_dmarc": True, "spf_aligned": True, "dkim_aligned": True, "disposition": "none", "org_name": "google.com"},
    {"date_begin": iso(1), "header_from": "riversidehealth.test", "source_ip_address": "185.1.1.1",
     "source_base_domain": "spoofer.example", "message_count": 37, "passed_dmarc": False,
     "spf_aligned": False, "dkim_aligned": False, "disposition": "reject", "org_name": "Yahoo"},
    {"date_begin": iso(2), "header_from": "lakesidehealth.test", "source_ip_address": "40.107.1.2",
     "message_count": 500, "passed_dmarc": "true", "spf_aligned": "true", "dkim_aligned": "false",
     "disposition": "none", "org_name": "google.com"},
]

CALLS = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return parse_qs(raw.decode())

    def _auth_ok(self):
        if (self.headers.get("Authorization") or "").startswith(("Bearer ", "ApiKey ", "Basic ")):
            return True
        return bool(self.headers.get("X-Api-Key"))  # Hadrian's real auth scheme: bare key, no Authorization header

    def do_DELETE(self):
        self._send({"succeeded": True})

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path
        CALLS.append(("GET", p, q))
        if not self._auth_ok():
            return self._send({"error": "no auth"}, 401)
        # ---- Falcon
        if p == "/falcon/devices/queries/devices-scroll/v1":
            if "offset" not in q:
                return self._send({"resources": ["aid1", "aid2"], "meta": {"pagination": {"offset": "tok2"}}})
            return self._send({"resources": ["aid3", "aid4"], "meta": {"pagination": {"offset": ""}}})
        if p == "/falcon/devices/combined/host-groups/v1":
            return self._send({"resources": [{"id": "g1", "name": "RVH Workstations"}],
                               "meta": {"pagination": {"total": 1}}})
        if p == "/falcon/discover/queries/hosts/v1":
            return self._send({"resources": [d["id"] for d in DISCOVER], "meta": {"pagination": {"total": len(DISCOVER)}}})
        if p == "/falcon/discover/entities/hosts/v1":
            want = set(q.get("ids", []))
            return self._send({"resources": [d for d in DISCOVER if d["id"] in want]})
        if p == "/falcon/spotlight/combined/vulnerabilities/v1":
            flt = q.get("filter", [""])[0]
            assert set(q.get("facet", [])) == {"cve", "host_info", "remediation"}, q
            data = CLOSED_VULNS if "closed" in flt else OPEN_VULNS
            if "after" not in q:
                return self._send({"resources": data[:2], "meta": {"pagination": {"after": "p2" if len(data) > 2 else None}}})
            return self._send({"resources": data[2:], "meta": {"pagination": {"after": None}}})
        if p == "/falcon/alerts/queries/alerts/v2":
            return self._send({"resources": ["al1", "al2"], "meta": {"pagination": {"total": 2}}})
        # ---- Hadrian (real contract: /organizations/{id}/assets|risks, offset is a
        # PAGE INDEX not a row offset, wrapper is {totalCount, offset, pageSize, items})
        if "/hadrian/organizations/" in p and "/risks/" in p:
            rid = p.rsplit("/", 1)[1]
            r = next((x for x in HADRIAN_RISKS if x["id"] == rid), None)
            if r is None:
                return self._send({"title": "Not Found"}, 404)
            a = next(x for x in HADRIAN_ASSETS if x["assetId"] == HADRIAN_RISK_ASSET[rid])
            return self._send(dict(r, description=f"{r['title']} detail", remediation="Fix it",
                                   relatedAssets=[{k: a[k] for k in ("assetId", "value", "platformAssetType", "tags")}],
                                   relatedIssues=[]))
        if p.endswith("/assets") or p.endswith("/risks"):
            data = HADRIAN_ASSETS if p.endswith("assets") else HADRIAN_RISKS
            offset = int(q.get("offset", ["0"])[0])
            size = int(q.get("pageSize", ["1"])[0])
            chunk = data[offset * size: (offset + 1) * size]
            return self._send({"totalCount": len(data), "offset": offset, "pageSize": size, "items": chunk})
        # ---- Graph
        if p == "/graph/identityProtection/riskyUsers":
            if q.get("skip"):
                return self._send({"value": [{"id": "u2", "userPrincipalName": "b@lakesidehealth.test",
                                              "riskLevel": "medium", "riskState": "atRisk"}]})
            host = f"http://{self.headers['Host']}"
            return self._send({"value": [{"id": "u1", "userPrincipalName": "a@riversidehealth.test",
                                          "riskLevel": "high", "riskState": "confirmedCompromised",
                                          "riskLastUpdatedDateTime": iso(1)}],
                               "@odata.nextLink": f"{host}/graph/identityProtection/riskyUsers?skip=1"})
        if p == "/graph/identityProtection/riskDetections":
            return self._send({"value": [{"id": "d1", "userPrincipalName": "a@riversidehealth.test",
                                          "riskEventType": "unfamiliarFeatures", "riskLevel": "high",
                                          "riskState": "atRisk", "detectedDateTime": iso(1),
                                          "ipAddress": "1.2.3.4",
                                          "location": {"city": "Lagos", "countryOrRegion": "NG"}}]})
        if p == "/graph/reports/authenticationMethods/userRegistrationDetails":
            return self._send({"value": [
                {"id": "m1", "userPrincipalName": "a@riversidehealth.test", "userType": "member",
                 "isMfaRegistered": True, "isMfaCapable": True, "methodsRegistered": ["microsoftAuthenticatorPush"]},
                {"id": "m2", "userPrincipalName": "c@riversidehealth.test", "userType": "member",
                 "isMfaRegistered": False, "isMfaCapable": False, "methodsRegistered": []},
                {"id": "m3", "userPrincipalName": "guest_x#EXT#@rvh.onmicrosoft.com", "userType": "guest",
                 "isMfaRegistered": False}]})
        return self._send({"error": f"unmocked GET {p}"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        p = u.path
        body = self._body()
        CALLS.append(("POST", p, body))
        if p == "/falcon/oauth2/token":
            return self._send({"access_token": "tok", "expires_in": 1799})
        if p.endswith("/oauth2/v2.0/token"):
            return self._send({"access_token": "aztok", "expires_in": 3599})
        if p == "/hec/auth/external":
            assert body.get("clientId") and body.get("accessKey"), body
            return self._send({"success": True, "data": {"token": "hectok", "expiresIn": 1800}})
        if not self._auth_ok():
            return self._send({"error": "no auth"}, 401)
        if p == "/falcon/devices/entities/devices/v2":
            return self._send({"resources": [HOSTS[i] for i in body["ids"] if i in HOSTS]})
        if p == "/falcon/alerts/entities/alerts/v2":
            return self._send({"resources": [
                {"composite_id": "al1", "created_timestamp": iso(0, 5), "updated_timestamp": iso(0, 4),
                 "severity": 90, "severity_name": "Critical", "status": "new", "display_name": "Ransomware",
                 "tactic": "Impact", "technique": "Data Encrypted for Impact", "product": "epp",
                 "device": {"device_id": "aid1", "hostname": "RVH-WS01"}},
                {"composite_id": "al2", "created_timestamp": iso(0, 30), "updated_timestamp": iso(0, 6),
                 "severity": 50, "severity_name": "Medium", "status": "closed", "resolution": "false_positive",
                 "name": "Credential spray", "product": "idp", "user_name": "jo@lakesidehealth.test"},
            ]})
        if p == "/falcon/identity-protection/combined/graphql/v1":
            assert "entities(" in body["query"] and "__TYPES__" not in body["query"], body
            page = 1 if (body.get("variables") or {}).get("after") == "c1" else 0
            return self._send({"data": {"entities": IDENTITY_PAGES[page]}})
        if p == "/hec/app/hec-api/v1.0/event/query":
            assert self.headers.get("x-av-req-id")
            rd = body["requestData"]
            assert rd.get("startDate") and rd.get("endDate"), rd
            scroll = rd.get("scrollId")
            i = (int(scroll[1:]) + 1) if scroll else 0
            next_scroll = f"s{i}" if i + 1 < len(HEC_PAGES) else None
            return self._send({"responseEnvelope": {"scrollId": next_scroll},
                               "responseData": HEC_PAGES[i]})
        if p.startswith("/la/workspaces/"):
            day = (NOW - dt.timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
            return self._send({"tables": [{"name": "PrimaryResult", "columns": [
                {"name": "day", "type": "datetime"}, {"name": "key", "type": "string"},
                {"name": "dimension", "type": "string"}, {"name": "value", "type": "long"}],
                "rows": [[day, "a@riversidehealth.test", "failure", 12],
                         [day, "b@riversidehealth.test", "failure", 3],
                         [day, "z@lakesidehealth.test", "success", 40]]}]})
        if p.startswith("/os/") and p.endswith("/_search"):
            return self._send({"_scroll_id": "sc1", "hits": {"hits": [{"_source": h} for h in DMARC_HITS[:2]]}})
        if p == "/os/_search/scroll":
            if body.get("scroll_id") == "sc1":
                return self._send({"_scroll_id": "sc2", "hits": {"hits": [{"_source": h} for h in DMARC_HITS[2:]]}})
            return self._send({"_scroll_id": "sc2", "hits": {"hits": []}})
        return self._send({"error": f"unmocked POST {p}"}, 404)


def start(port=8999):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv
