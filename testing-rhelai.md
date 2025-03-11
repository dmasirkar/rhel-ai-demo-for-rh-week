# This document provides a vulnerability and CVE related information about httpd, openssl, openssh, kernel and samba packages in Red Hat Enterprise Linux 9.

## Vulnerability and CVE related information about httpd

### The httpd in Red Hat Enterprise Linux 9 (RHEL) stands for HyperText Transfer Daemon, commonly known as Apache HTTP Server. Apache HTTP Server is an open-source web server software that powers many of the world's websites.The Red Hat Enterprise Linux 9 provides httpd-2.4.62 version of the Apache HTTP Server.
https://raw.githubusercontent.com/dmasirkar/rhel-ai-demo-for-rh-week/refs/heads/main/testing-rhelai.md
### 1) CVE-2024-38473 :

#### Description :

 A flaw was found in the mod_proxy module of httpd. Due to an encoding problem, specially crafted request URLs with incorrect encoding can be sent to backend services, potentially bypassing authentication.

#### Statement :

This issue affects configurations where mechanisms other than ProxyPass/ProxyPassMatch or RewriteRule with the 'P' flag are used to configure a request to be proxied, such as SetHandler or inadvertent proxying via CVE-2024-39573. Note that these alternate mechanisms may be used within .htaccess files.
For more information about CVE-2024-39573, see https://access.redhat.com/security/cve/CVE-2024-39573.
Additionally, this flaw requires mod_proxy to be loaded and being used. This module can be disabled if its functionality is not needed.

#### Solution :

CVE-2024-38473 is fixed in httpd-2.4.57-11.el9_4 package version in Red Hat Enterprise Linux (RHEL) 9.4 and Red Hat Enterprise Linux (RHEL) 9.5. 
    If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:
           `# dnf update httpd`
    For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:4726

### 2) CVE-2024-38474 :

#### Description :

A flaw CVE-2024-38474 was found in the mod_rewrite module of httpd. Due to a substitution encoding issue, specially crafted requests may allow an attacker to execute scripts in directories permitted by the configuration but not directly reachable by any URL or source disclosure of scripts meant only to be executed as CGI.

#### Statement :

This issue only affects configurations with unsafe rules used in the RewriteRule directive. Also, to exploit this flaw, an attacker must be able to upload files to the server. For these reasons, this flaw was rated with an important and not critical severity.
Additionally, this flaw requires mod_rewrite to be loaded and used. This module can be disabled if its functionality is not needed.

#### Solution :

CVE-2024-38474 is fixed in httpd-2.4.57-11.el9_4 package version in Red Hat Enterprise Linux (RHEL) 9.4 and Red Hat Enterprise Linux (RHEL) 9.5. 
If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:
        ` # dnf update httpd`
For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:4726 

### 3) CVE-2024-38475 :

#### Description

A flaw was found in the mod_rewrite module of httpd. Improper escaping of output allows an attacker to map URLs to filesystem locations permitted to be served by the server but are not intentionally or directly reachable by any URL. This issue results in code execution or source code disclosure.

#### Statement

This issue affects configurations with substitution rules used in the RewriteRule directive using backreferences or variables as the first segment of the substitution.Additionally, this flaw requires mod_rewrite to be loaded and used. This module can be disabled if its functionality is not needed.

##### Solution :

CVE-2024-38475 is fixed in httpd-2.4.57-11.el9_4 package version in Red Hat Enterprise Linux (RHEL) 9.4 and Red Hat Enterprise Linux (RHEL) 9.5. 
If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:
        ` # dnf update httpd`
For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:4726 

### 4) CVE-2024-38477 :

#### Description :

 A flaw was found in the mod_proxy module of httpd. A NULL pointer dereference can be triggered when processing a specially crafted HTTP request, causing the httpd server to crash, and resulting in a denial of service.

#### Statement :

  As this flaw allows a remote attacker to cause a denial of service, it has been rated with an important severity.
  This flaw only affects configurations with mod_proxy loaded and being used. This module can be disabled via the configuration file if its functionality is not being used.

#### Solution :

CVE-2024-38477 is fixed in httpd-2.4.57-11.el9_4 package version in Red Hat Enterprise Linux (RHEL) 9.4 and Red Hat Enterprise Linux (RHEL) 9.5. 
If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:
        ` # dnf update httpd`
For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:4726 

### 5) CVE-2024-39573 :

#### Description :

A flaw was found in the mod_rewrite module of httpd. A potential SSRF allows an attacker to cause unsafe rules used in the RewriteRule directive to unexpectedly set up URLs to be handled by the mod_proxy module.

#### Statement :

This issue only affects configurations with unsafe rules used in the RewriteRule directive.Additionally, this flaw requires mod_rewrite and mod_proxy to be loaded and being used. These modules can be disabled via the configuration file if their functionality are not needed.

#### Solution :

CVE-2024-39573 is fixed in httpd-2.4.57-11.el9_4 package version in Red Hat Enterprise Linux (RHEL) 9.4 and Red Hat Enterprise Linux (RHEL) 9.5. 
If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:
        ` # dnf update httpd`
For more details refer Red Hat Security Advisory https://access.redhat.com/erra

This file provide the vulnerability and CVE related data for httpd package available in Red Hat Enterprise Linux 9.ta/RHSA-2024:4726

### 6) CVE-2023-38709 :

#### Description :

 A flaw was found in httpd. The response headers are not sanitized before an HTTP response is sent when a malicious backend can insert a Content-Type, Content-Encoding, or some other headers, resulting in an HTTP response splitting.

#### Statement :

This flaw is only exploitable by a malicious backend or a malicious application, but may also affect forward proxy configurations.

#### Solution :

CVE-2024-39573 is fixed in httpd-2.4.62-1.el9 package version in Red Hat Enterprise Linux (RHEL) 9.5.If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:
        ` # dnf update httpd`

For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:9306

### 7) CVE-2024-24795 :

#### Description

A flaw was found in httpd. An HTTP response splitting in mStatementultiple httpd modules may allow an attacker that can inject malicious response headers into backend applications to cause an HTTP desynchronization attack.

#### Statement :

This flaw only affects configurations when at least one of the following modules is loaded and being used: mod_authnz_fcgi, mod_cgi, mod_cgid, mod_proxy_fcgi, mod_proxy_scgi and mod_proxy_uwsgi. Additionally, this flaw is only exploitable by a malicious backend in a reverse proxy configuration or an attack against a backend application that inserts headers.
These modules are enabled by default in Red Hat Enterprise Linux 9. These modules can be disabled via the configuration file if their functionality is not being used.

#### Solution :

CVE-2024-39573 is fixed in httpd-2.4.62-1.el9 package version in Red Hat Enterprise Linux (RHEL) 9.5.If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:

        ` # dnf update httpd`

For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:9306

### 8) CVE-2024-38476 :

#### Description

   A flaw was found in httpd. Backend applications whose response headers are malicious or exploitable may allow information disclosure, server-side request forgery (SSRF) or local script execution.

#### Statement

   This flaw can only be exploited by backend applications via malicious or exploitable response headers. For this reason, this flaw was rated with an important and not critical severity.

#### Solution :

CVE-2024-38476 is fixed in httpd-2.4.57-11.el9_4.1 package version in Red Hat Enterprise Linux (RHEL) 9.5.If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:

        ` # dnf update httpd`

For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:5138

### 9) CVE-2023-25690 :

#### Description

A vulnerability was found in httpd. This security issue occurs when some mod_proxy configurations on Apache HTTP Server allow an HTTP Request Smuggling attack. Configurations are affected when mod_proxy is enabled along with some form of RewriteRule or ProxyPassMatch in which a non-specific pattern matches some portion of the user-supplied request-target (URL) data and is then re-inserted into the proxied request-target using variable substitution.

#### Solution :

CVE-2023-25690 is fixed in httpd-2.4.53-7.el9_1.5 package version in Red Hat Enterprise Linux (RHEL) 9.1 and later.If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:

        ` # dnf update httpd`

For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2023:1670

### 10) CVE-2022-37436 :

#### Description

A flaw was found in the mod_proxy module of httpd. A malicious backend can cause the response headers to be truncated because they are not cleaned when an error is found while reading them, resulting in some headers being incorporated into the response body and not being interpreted by a client.

#### Statement

This flaw is only exploitable via bad headers generated by a malicious backend or a malicious application.The httpd as shipped in Red Hat Enterprise Linux 9 is vulnerable to this flaw.

#### Solution :

CVE-2022-37436 is fixed in httpd-2.4.53-7.el9_1.1.package version in Red Hat Enterprise Linux (RHEL) 9.1 and later.If the system is not already updated to latest version of httpd then use following command to update httpd package to the latest version:

        ` # dnf update httpd`

For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2023:0970

## Vulnerability and CVE related data for samba package

### 1) `CVE-2023-3347`

#### Description
A vulnerability was found in Samba's SMB2 packet signing mechanism. The SMB2 packet signing is not enforced if an admin configured "server signing = required" or for SMB2 connections to Domain Controllers where SMB2 packet signing is mandatory. This flaw allows an attacker to perform attacks, such as a man-in-the-middle attack, by intercepting the network traffic and modifying the SMB2 messages between client and server, affecting the integrity of the data.

#### Statement
This CVE only affects Samba starting with 4.17.0 and higher versions.

#### Solution
The SMB2 packet signing is not enforced if an admin configured "server signing = required" or for SMB2 connections to Domain Controllers where SMB2 packet signing is mandatory. 

Apply the following bugfixes:
RHEL9: RHSA-2023:4328 - Security Advisory
RHEL8: RHSA-2023:4325 - Security Advisory



### 2) `CVE-2023-4091`

#### Description
A vulnerability was discovered in Samba, where the flaw allows SMB clients to truncate files, even with read-only permissions when the Samba VFS module "acl_xattr" is configured with "acl_xattr:ignore system acls = yes". The SMB protocol allows opening files when the client requests read-only access but then implicitly truncates the opened file to 0 bytes if the client specifies a separate OVERWRITE create disposition request. The issue arises in configurations that bypass kernel file system permissions checks, relying solely on Samba's permissions.

#### Statement
The vulnerability primarily affects Samba configurations using the "acl_xattr" module with the "acl_xattr:ignore system acls = yes" setting.

#### Solution
The vulnerability is most commonly associated with the "acl_xattr" module and can be mitigated by setting:

`acl_xattr:ignore system acls = no`

For more details refer to https://access.redhat.com/security/cve/cve-2023-4091

### 4) `CVE-2023-4154`

#### Description

A design flaw was found in Samba's DirSync control implementation, which exposes passwords and secrets in Active Directory to privileged users and Read-Only Domain Controllers (RODCs). This flaw allows RODCs and users possessing the GET_CHANGES right to access all attributes, including sensitive secrets and passwords. Even in a default setup, RODC DC accounts, which should only replicate some passwords, can gain access to all domain secrets, including the vital krbtgt, effectively eliminating the RODC / DC distinction. Furthermore, the vulnerability fails to account for error conditions (fail open), like out-of-memory situations, potentially granting access to secret attributes, even under low-privileged attacker influence.

#### Solution 

The Samba package as shipped with Red Hat Enterprise Linux 6, 7, 8 and 9 and Red Hat Gluster Storage is not affected by this issue as Red Hat doesn't provide the AD Domain Controller capability with it.



### 5) `CVE-2023-42669`

#### Description 
A vulnerability was found in Samba's "rpcecho" development server, a non-Windows RPC server used to test Samba's DCE/RPC stack elements. This vulnerability stems from an RPC function that can be blocked indefinitely. The issue arises because the "rpcecho" service operates with only one worker in the main RPC task, allowing calls to the "rpcecho" server to be blocked for a specified time, causing service disruptions. This disruption is triggered by a "sleep()" call in the "dcesrv_echo_TestSleep()" function under specific conditions. Authenticated users or attackers can exploit this vulnerability to make calls to the "rpcecho" server, requesting it to block for a specified duration, effectively disrupting most services and leading to a complete denial of service on the AD DC. The DoS affects all other services as "rpcecho" runs in the main RPC task.

#### Solution
To mitigate this vulnerability, disable rpcecho service on the AD DC by setting:
dcerpc endpoint servers = -rpcecho


### 6) `CVE-2023-0225`

#### Description
A vulnerability was found in Samba. This security issue occurs as an incomplete access check on the dnsHostName allows authenticated but otherwise, unprivileged users to delete this attribute from any object in the directory.

#### Statement or Solution
The samba package as shipped with Red Hat Enterprise Linux 6, 7, 8 and 9 and Red Hat Gluster is not affected by this issue as Red Hat doesn't provide the AD domain controller capability with it.


## Vulnerability and CVE related data for openssh package
The openssh package is pre-installed on RHEL system. 
OpenSSH is OpenBSD's version of the last free version of SSH, bringing it up to date in terms of security and features.

This package includes the core files necessary for both the OpenSSH client and server. To make this package useful, you should also install openssh-clients, openssh-server, or both.The openssh package is pre-installed on RHEL system. 

OpenSSH is OpenBSD's version of the last free version of SSH, bringing it up to date in terms of security and features.

## CVEs covered in this document 

This document is specifically created for details for following CVEs related to openssh package on RHEL 9. 

CVE-2023-48795
CVE-2023-51385
CVE-2024-6387
CVE-2024-6409
CVE-2024-7589

Lets dive deep into each of the vulnerabilities for more details. 

## CVE-2023-48795

- The vulnerability or CVE CVE-2023-48795
 is also referred to as terrapin attack.
- This affects openssh packages on RHEL.

### Description
A flaw was found in the SSH channel integrity. By manipulating sequence numbers during the handshake, an attacker can remove the initial messages on the secure channel without causing a MAC failure. For example, an attacker could disable the ping extension and thus disable the new countermeasure in OpenSSH 9.5 against keystroke timing attacks.

### Mitigation
Update to the last version and check that client and server provide kex pseudo-algorithms indicating usage of the updated version of the protocol which is protected from the attack. If "kex-strict-c-v00@openssh.com" is provided by clients and "kex-strict-s-v00@openssh.com" is in the server's reply, no other steps are necessary.

Disabling ciphers if necessary:

If "kex-strict-c-v00@openssh.com" is not provided by clients or "kex-strict-s-v00@openssh.com" is absent in the server's reply, you can disable the following ciphers and HMACs as a workaround on RHEL-8 and RHEL-9:

1. chacha20-poly1305@openssh.com
2. hmac-sha2-512-etm@openssh.com
3. hmac-sha2-256-etm@openssh.com
4. hmac-sha1-etm@openssh.com
5. hmac-md5-etm@openssh.com

To do that through crypto-policies, one can apply a subpolicy with the following content:
```
cipher@SSH = -CHACHA20-POLY1305
ssh_etm = 0
```
e.g., by putting these lines into `/etc/crypto-policies/policies/modules/CVE-2023-48795.pmod`, applying the resulting subpolicy with `update-crypto-policies --set $(update-crypto-policies --show):CVE-2023-48795` and restarting openssh server.
One can verify that the changes are in effect by ensuring the ciphers listed above are missing from both `/etc/crypto-policies/back-ends/openssh.config` and `/etc/crypto-policies/back-ends/opensshserver.config`.

For more details on using crypto-policies, please refer to https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening

Note that this procedure does limit the interoperability of the host and is only suggested as a temporary mitigation until the issue is fully resolved with an update.

### Solution 
Fix for CVE-2023-48795 is released as 	RHSA-2024:1130 on 5th March 2024. For details on fix refer errata link https://access.redhat.com/errata/RHSA-2024:1130

To fix vulnerability, update the openssh package to version 8.7p1-34.el9_3.3.x86_64. 

```
$ dnf update openssh*
```
The errata details are available on https://access.redhat.com/errata/RHSA-2024:1130 referred as RHSA-2024:1130 in short. 

For details on how to apply this update, which includes the changes described in this advisory, refer to:=
https://access.redhat.com/articles/11258

## CVE-2023-51385

- This affects openssh packages on RHEL.
- A remote attacker may be able to execute arbitrary OS commands by using expansion tokens, such as %u or %h

### Description
A flaw was found in OpenSSH. In certain circumstances, a remote attacker may be able to execute arbitrary OS commands by using expansion tokens, such as %u or %h, with user names or host names that contain shell metacharacters.

### Statement
The ability to execute OS commands is dependent on what quoting is present in the user-supplied ssh_config directive. However, it is generally the user's responsibility to validate arguments passed to SSH.

### Mitigation
Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base or stability.

### Solution 
Fix for CVE-2023-51385 is released as RHSA-2024:1130 on 5th March 2024. For details on fix refer errata link https://access.redhat.com/errata/RHSA-2024:1130

To fix vulnerability, update the openssh package to version 8.7p1-34.el9_3.3.x86_64. 
```
$ dnf update openssh*
```
The errata details are available on https://access.redhat.com/errata/RHSA-2024:1130 referred as RHSA-2024:1130 in short. 

CVE-2023-48795
CVE-2023-51385

## CVE-2024-6387

- This affects openssh packages on RHEL.
- A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd).

### Description
A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

### Statement
Red Hat rates the severity of this flaw as Important for both Red Hat Enterprise Linux (RHEL) and OpenShift Container Platform (OCP). The most significant risk is Remote Code Execution, however this outcome requires significant resources to exploit. If mitigations are put in place, the consequences of exploitation are reduced. An attacker would then only be able to impact availability of the OpenSSH service.

The main factor preventing a higher impact rating is an unpredictable race condition. All actively supported versions of RHEL (and by extension OCP) have ExecShield (aka ASLR) enabled by default and utilize NX technology, reducing reliability of the attack. Attackers are forced to retry the attack thousands of times. This generates significant noise providing defenders with an opportunity to detect and disrupt potential attacks.

RHEL 9 is the only affected version. RHEL 6, 7, and 8 all utilize an older version of OpenSSH which was never affected by this vulnerability.

### Mitigation
The below process can protect against a Remote Code Execution attack by disabling the LoginGraceTime parameter on Red Hat Enterprise Linux 9. However, the sshd server is still vulnerable to a Denial of Service if an attacker exhausts all the connections.

1) As root user, open the /etc/ssh/sshd_config
2) Add or edit the parameter configuration:
```
$ vi /etc/ssh/sshd_config
LoginGraceTime 0
```
3) Save and close the file
4) Restart the sshd daemon:
```
$ systemctl restart sshd.service
```
Setting LoginGraceTime to 0 disables the SSHD server's ability to drop connections if authentication is not completed within the specified timeout. If this mitigation is implemented, it is highly recommended to use a tool like 'fail2ban' alongside a firewall to monitor log files and manage connections appropriately.

If any of the mitigations mentioned above is used, please note that the removal of LoginGraceTime parameter from sshd_config is not automatic when the updated package is installed.

### Solution

The fix for CVE-2024-6387 has been released as https://access.redhat.com/errata/RHSA-2024:4312 and vulnerability if fixed in openssh version 8.7p1-38.el9_4.1.x86_64.

To fix vulnerability, update openssh package to version 8.7p1-38.el9_4.1.x86_64.rpm or higher. If already on higher version, you are not affected by the vulnerability. 
```
$ dnf update openssh*
```
For details refer RHSA link https://access.redhat.com/errata/RHSA-2024:4312

For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258

## CVE-2024-6409

- This affects openssh packages on RHEL.
- A race condition vulnerability was discovered in how signals are handled by OpenSSH's server (sshd)

### Description
A race condition vulnerability was discovered in how signals are handled by OpenSSH's server (sshd). If a remote attacker does not authenticate within a set time period, then sshd's SIGALRM handler is called asynchronously. However, this signal handler calls various functions that are not async-signal-safe, for example, syslog(). As a consequence of a successful attack, in the worst case scenario, an attacker may be able to perform a remote code execution (RCE) as an unprivileged user running the sshd server.

### Statement
Red Hat rates the severity of this flaw as Moderate for both Red Hat Enterprise Linux (RHEL) and OpenShift Container Platform (OCP). While there are many similarities to CVE-2024-6387, the important difference is that any possible remote code execution is limited to an unprivileged child of the SSHD server. This additional restriction on access reduces the overall security impact.

This vulnerability only affects the versions of OpenSSH shipped with Red Hat Enterprise Linux 9. Upstream versions of sshd are not impacted by this flaw.

### Mitigation
The process is identical to CVE-2024-6387, by disabling LoginGraceTime. See that CVE page for additional details.

### Solution 
The fix for CVE-2024-6409 has been released as https://access.redhat.com/errata/RHSA-2024:4457 and vulnerability if fixed in openssh version 8.7p1-38.el9_4.4.x86_64.

To fix vulnerability, update openssh package to version 8.7p1-38.el9_4.4.x86_64 or higher. If already on higher version, you are not affected by the vulnerability. 
```
$ dnf update openssh*
```
For details refer RHSA link https://access.redhat.com/errata/RHSA-2024:4457

For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258

## CVE-2024-7589

- This does not affect openssh packages on RHEL.
- This vulnerability is specific to the FreeBSD distribution of OpenSSH.

### Description
A signal handler in sshd(8) may call a logging function that is not async-signal-safe. The signal handler is invoked when a client does not authenticate within the LoginGraceTime seconds (120 by default). This signal handler executes in the context of the sshd(8)'s privileged code, which is not sandboxed and runs with full root privileges. This issue is another instance of the problem in CVE-2024-6387 addressed by FreeBSD-SA-24:04.openssh. The faulty code in this case is from the integration of blacklistd in OpenSSH in FreeBSD. As a result of calling functions that are not async-signal-safe in the privileged sshd(8) context, a race condition exists that a determined attacker may be able to exploit to allow an unauthenticated remote code execution as root.

### Statement
This vulnerability is specific to the FreeBSD distribution of OpenSSH. Red Hat Products are not affected.

### Mitigation
As this does not affect openssh package on RHEL, there is no mitigation applicable. 

### Solution 
There is no action required as this vulnerability is specific to the FreeBSD distribution of OpenSSH. Red Hat Products are not affected.

## Configuration vulnerabilities in openssh

### SSH Server Supports Weak Key Exchange Algorithms

The diffie-hellman-group1-sha1 key exchange algorithm is already disabled in DEFAULT system-wide cryptographic policy in Red Hat Enterprise Linux 8 and 9.
For more details, read this solution:

Steps to disable the diffie-hellman-group1-sha1 algorithm in SSH https://access.redhat.com/solutions/4278651

### SSH CBC Mode Ciphers Enabled

To remove the CBC algorithm from the server for sshd, modify ssh_cipher in /etc/crypto-policies/policies/modules/DISABLE-CBC.pmod for Red Hat Enterprise Linux 8 and 9:
```
$ vi /etc/crypto-policies/policies/modules/DISABLE-CBC.pmod
ssh_cipher = -AES-128-CBC -AES-256-CBC
```
Once done, apply the new policy:
```
$ sudo update-crypto-policies --set DEFAULT:DISABLE-CBC
```

For more details, read this solution: https://access.redhat.com/articles/7041246

### SSH Insecure HMAC Algorithms Enabled
The diffie-hellman-group1-sha1 key exchange algorithm is already disabled in DEFAULT system-wide cryptographic policy in Red Hat Enterprise Linux 8 and 9.
For more details, read this solution: https://access.redhat.com/solutions/4278651

### Terrapin Attack (CVE-2023-48795)

You can disable the following ciphers and HMACs as a workaround on Red Hat Enterprise Linux 8 and 9:

chacha20-poly1305@openssh.com
hmac-sha2-512-etm@openssh.com
hmac-sha2-256-etm@openssh.com
hmac-sha1-etm@openssh.com
hmac-md5-etm@openssh.com

To do that through crypto-policies, put these lines into `/etc/crypto-policies/policies/modules/CVE-2023-48795.pmod`:/
```
$ vi /etc/crypto-policies/policies/modules/CVE-2023-48795.pmod
cipher@SSH = -CHACHA20-POLY1305
ssh_etm = 0
```

Once done, apply the new policy:
```
$ sudo update-crypto-policies --set $(update-crypto-policies --show):CVE-2023-48795
```
One can verify that the changes are in effect by ensuring the ciphers listed above are missing from both `/etc/crypto-policies/back-ends/openssh.config` and `/etc/crypto-policies/back-ends/opensshserver.config`.

### Validation

To list all supported ciphers by ssh server, there are two alternatives as below :

1. Using nmap
```
$ nmap --script ssh2-enum-algos -sV -p 22 127.0.0.1
```
This command lists supported algorithms including key exchange,encryption, MAC, compression algorithms

2. Using sshd command utility
```
$ sshd -T | egrep "cipher|mac|kexalgorithm"
```
SSHD should support only strong set of ciphers, protocols and kexalgorithms. 
These commands are also used to validate and confirm if sshd configuration vulnerabilities are fixed. 

## Vulnerability and CVE related data for openssl package

1. CVE-2024-12797  
   1. Description  
        
      A flaw was found in OpenSSL's RFC7250 Raw Public Key (RPK) authentication. This vulnerability allows man-in-the-middle (MITM) attacks via failure to abort TLS/DTLS handshakes when the server's RPK does not match the expected key despite the SSL\_VERIFY\_PEER verification mode being set.  
        
   2. Statement  
        
      The version of OpenSSL in RHEL-9.5 is affected by this vulnerability. However, earlier releases of OpenSSL in RHEL are not affected. This issue was introduced in the initial implementation of RPK support in OpenSSL 3.2.  
        
      RPKs are disabled by default in both TLS clients and TLS servers. The issue only arises when TLS clients explicitly enable RPK use by the server, and the server, likewise, enables sending of an RPK instead of an X.509 certificate chain. The affected clients are those that then rely on the handshake to fail when the server's RPK fails to match one of the expected public keys, by setting the verification mode to SSL\_VERIFY\_PEER.  
        
      Clients that enable server-side raw public keys can still find out that raw public key verification failed by calling SSL\_get\_verify\_result(), and those that do, and take appropriate action, are not affected.  
        
      rhel9/ruby-33 & ubi9/ruby-33 are not affected because RPK is not present in any form or as any function that could be called from Ruby via Red Hat supported RPMs in RHEL. For example the SSL\_dane\_enable or SSL\_add\_expected\_rpk or X509\_STORE\_CTX\_get0\_rpk or X509\_STORE\_CTX\_init\_rpk (and more rpk-related) functions are not callable from Ruby.  
        
        
   3. Solution

      CVE-2024-12797 is fixed in openssl-3.2.2-6.el9\_5.1 package version. 

      If the system is not already updated to latest version then refer command as follows:

       \# dnf update openssl

      For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2025:1330 


2. CVE-2024-6119  
   1. Description  
        
      A flaw was found in OpenSSL. Applications performing certificate name checks (e.g., TLS clients checking server certificates) may attempt to read an invalid memory address resulting in abnormal termination of the application process.  
        
   2. Statement  
        
      This vulnerability is classified as moderate severity rather than important because it primarily affects specific use cases involving certificate name checks against otherName subject alternative names, a scenario that is not commonly encountered. The issue only triggers a denial of service (DoS) by causing an abnormal application termination, without compromising the integrity, confidentiality, or availability of data at a broader scale. Additionally, TLS servers, which typically don't perform reference identity checks during client certificate validation, are largely unaffected. The impact is localized to certain TLS clients performing specific name comparisons, reducing the overall risk profile and justifying the moderate severity classification.  
        
   3. Solution

      CVE-2024-6119 is fixed in openssl-3.0.7-28.el9\_4 and edk2-ovmf-20231122-6.el9\_4.4 package version. 

      If the system is not already updated to latest version then refeVulnerability and CVE related data for
      For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:6783 and https://access.redhat.com/errata/RHSA-2024:8935


3. CVE-2024-5535  
   1. Description  
        
      A flaw was found in OpenSSL. Affected versions of this package are vulnerable to Information Exposure through the SSL\_select\_next\_proto function. This flaw allows an attacker to cause unexpected application behavior or a crash by exploiting the buffer overread condition when the function is called with a zero-length client list. This issue is only exploitable if the application is misconfigured to use a zero-length server list and mishandles the 'no overlap' response in ALPN or uses the output as the opportunistic protocol in NPN.  
        
   2. Statement  
        
      The FIPS modules in versions 3.3, 3.2, 3.1, and 3.0 are not affected by this issue. The packages shim and shim-unsigned-x64 are not impacted by this CVE, as the affected OpenSSL code path is not utilized.  
        
   3. Solution

      CVE-024-5535 is fixed in openssl-3.2.2-6.el9\_5 and mysql-8.0.41-2.el9\_5 package version. 

      If the system is not already updated to latest version then refer command as follows:

       \# dnf update openssl

      For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:9333 and https://access.redhat.com/errata/RHSA-2025:1671


4. CVE-2024-2511  
   1. Description  
        
      A flaw was found in OpenSSL. A malicious client can trigger an uncontrolled memory consumption, resulting in a Denial of Service. This issue occurs due to OpenSSL's TLSv3.1 session cache going into an incorrect state, leading to it failing to flush properly as it fills. OpenSSL must be configured with the non-default SSL\_OP\_NO\_TICKET option enabled to be vulnerable. This issue only affects TLSv1.3 servers, while TLS clients are not affected.  
        
   2. Statement  
        
      The OpenSSL version shipped with Red Hat Enterprise Linux 7 is not affected by this issue, as the version 1.0.2 does not contain the related bug.  
        
   3. Solution

      CVE-2024-2511 is fixed in openssl-3.2.2-6.el9\_5 package version. 

      If the system is not already updated to latest version then refer command as follows:

       \# dnf update openssl

      For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:9333

      
5. CVE-2024-4603  
   1. Description  
        
      A flaw was found in OpenSSL. Applications that use the EVP\_PKEY\_param\_check() or EVP\_PKEY\_public\_check() function to check a DSA public key or DSA parameters may experience long delays when checking excessively long DSA keys or parameters.  In applications that allow untrusted sources to provide the key or parameters that are checked, an attacker may be able to cause a denial of service. These functions are not called by OpenSSL on untrusted DSA keys. The applications that directly call these functions are the ones Vulnerability and CVE related data forthat may be vulnerable to this issue.  
        
   2. Statement  
        
      Only OpenSSL 3.3, 3.2, 3.1 and 3.0 are vulnerable to this issue. OpenSSL 1.1.1 and 1.0.2 are not affected by this issue.  
        
   3. Solution

      CVE-2024-4603 is fixed in openssl-3.2.2-6.el9\_5 package version. 

      If the system is not already updated to latest version then refer command as follows:

       \# dnf update openssl

      For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:9333


6. CVE-2024-4741  
   1. Description  
        
      A use-after-free vulnerability was found in OpenSSL. Calling the OpenSSL API SSL\_free\_buffers function may cause memory to be accessed that was previously freed in some situations.  
        
   2. Statement  
        
      This vulnerability is classified as low severity rather than moderate because it only affects applications that explicitly call SSL\_free\_buffers, a rarely used OpenSSL function.  
      The issue arises in specific conditions where the function is called while a buffer is still in use, leading to a potential use-after-free scenario. However, exploitation is significantly constrained because  
        
         1. an application must intentionally invoke this function, which is not typical in common OpenSSL usage,  
         2. triggering the vulnerability requires precise timing and conditions where partially processed records remain unread or incomplete, and  
         3. There are no known active exploits leveraging this issue.

		  
      Given these factors, while the bug could theoretically lead to crashes or corruption, the practical risk of widespread exploitation remains minimal.

   3. Solution

      CVE-2024-4741 is fixed in openssl-3.2.2-6.el9\_5 package version. 

      If the system is not already updated to latest version then refer command as follows:

       \# dnf update openssl

      For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:9333


7. CVE-2023-6129  Vulnerability and CVE related data for
   1. Description  
        
      A flaw was found in the POLY1305 MAC (message authentication code) implementation in OpenSSL, affecting applications running on PowerPC CPU-based platforms that utilize vector instructions, and has the potential to corrupt the internal state of these applications. If an attacker can manipulate the utilization of the POLY1305 MAC algorithm, it may lead to the corruption of the application state, resulting in various application-dependent consequences, often resulting in a crash and leading to a denial of service.  
        
   2. Statement  
        
      This vulnerability is categorized as having a Low severity due to the limited scope of its potential impact and the specific conditions required for exploitation. The vulnerability arises in the POLY1305 MAC implementation within OpenSSL on PowerPC CPUs, affecting newer processors supporting PowerISA 2.07 instructions. The issue involves the restoration of vector registers in a different order than they are saved, potentially corrupting application state upon return to the caller. The impact varies, contingent on the application's reliance on non-volatile XMM registers, ranging from incorrect calculations to potential denial of service. However, the practical exploitation of this vulnerability requires an attacker to influence the use of the POLY1305 MAC algorithm. Given the specific conditions needed for exploitation and the absence of concrete instances of affected applications, the overall risk is assessed as low. Additionally, the severity is tempered by the assumption that the most likely outcome is limited to incorrect results in application-dependent calculations or crashes, rather than enabling a full compromise of the application process.  
        
   3. Solution

      CVE-2023-6129 is fixed in openssl-3.0.7-27.el9 and edk2-ovmf-20240524-6.el9\_5 package version. 

      If the system is not already updated to latest version then refer command as follows:

       \# dnf update openssl

       \# dnf  update edk2-ovm

      For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:2447 and https://access.redhat.com/errata/RHSA-2024:9088


8. CVE-2023-6237  
   1. Description  
        
      A flaw was found in OpenSSL. When the EVP\_PKEY\_public\_check() function is called in RSA public keys, a computation is done to confirm that the RSA modulus, n, is composite. For valid RSA keys, n is a product of two or more large primes and this computation completes quickly. However, if n is a large prime, this computation takes a long time. An application that calls EVP\_PKEY\_public\_check() and supplies an RSA key obtained from an untrusted source could be vulnerable to a Denial of Service attack.  
        
   2. Statement  
        
      Red Hat Product Security rates the severity of this flaw as determined by the upstream OpenSSL security team.  
        
      The marked moderate issue in OpenSSL involves a flaw in the EVP\_PKEY\_public\_check() function used for RSA public keys. When verifying keys, the computation to confirm the composite nature of the RSA modulus may take an extended time if the modulus is a large prime. This vulnerability could be exploited for a Denial of Service attack in applications using this function with RSA keys from untrusted sources. The severity is moderate as it requires specific conditions for exploitation and may not pose an immediate widespread threat.  
        
   3. Solution

      CVE-2023-6237 is fixed in openssl-3.0.7-27.el9 and edk2-ovmf-20240524-6.el9\_5 package version. 

      If the system is not already updated to latest version then refer command as follows:

       \# dnf update openssl

       \# dnf  update edk2-ovm

      For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:2447 and https://access.redhat.com/errata/RHSA-2024:9088

## Vulnerability and CVE related information for kernel package

### 1) `CVE-2024-26735`

#### Description

A use-after-free flaw was found in the Linux kernel’s IPv6 protocol functionality. This flaw allows a local user to potentially crash the system.

#### Statement

In the Linux kernel, the following vulnerability has been resolved:

    ipv6: sr: fix possible use-after-free and null-ptr-deref

The pernet operations structure for the subsystem must be registered before registering the generic netlink family.

#### Solution

`CVE-2024-26735` is fixed in `kernel-5.14.0-427.20.1.el9_4` for Red Hat Enterprise Linux 9. This CVE does not affect `kernel-rt`. Red Hat recommends to update kernel to above release using `dnf update kernel` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory
https://access.redhat.com/errata/RHSA-2024:3619.

### 2) `CVE-2024-26993`

#### Description

The flaw was found in `sysfs_break_active_protection` routine which has an obvious reference leak in its error path.
If the call to kernfs_find_and_get() fails then kn will be NULL, so the companion sysfs_unbreak_active_protection() routine won't get called (and would only cause an access violation by trying to dereference kn->parent if it was called). As a result, the reference to kobj acquired at the start of the function will never be released. Fix the leak by adding an explicit kobject_put() call when kn is NULL.

#### Statement

In the Linux kernel, this vulnerability has been resolved as `fs: sysfs: Fix reference leak in sysfs_break_active_protection()`. The Linux kernel CVE team has assigned `CVE-2024-26993` to this issue.

#### Solution

`CVE-2024-26993` is fixed in `kernel-5.14.0-427.20.1.el9_4` for Red Hat Enterprise Linux 9. The fix for `kernel-rt` is released in `kernel-rt-5.14.0-427.20.1.el9_4`.
Red Hat recommends to update the respective kernel and kernel-rt version to above release or later using `dnf update kernel` or `dnf update kernel-rt` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:3619.

### 3) `CVE-2024-50154`

#### Description

A use-after-free (UAF) vulnerability was found and fixed in the Linux kernel's TCP subsystem related to request socket (reqsk) timers during handshake handling. This issue stems from a race condition caused by relying on timer_pending() in reqsk_queue_unlink(). This could result in the timer continuing to run after the socket (req->sk) is freed, allowing BPF programs to access invalid memory.

#### Statement

This vulnerability is classified as moderate severity rather than important because the issue primarily affects a narrow set of conditions, notably when BPF programs are involved in tracing TCP retransmissions. In most scenarios, the reqsk timer is pinned and the race condition is unlikely to be triggered. Additionally, the problem only occurs if the request socket (req->sk) is closed while the timer is still pending, which is an uncommon sequence of events. While the potential for a use-after-free (UAF) exists, it requires specific timing and conditions to exploit, limiting its overall risk and impact on typical systems.

#### Solution

`CVE-2024-50154` is fixed in `kernel-5.14.0-503.22.1.el9_5` for Red Hat Enterprise Linux 9. The fix for `kernel-rt` is released in `kernel-rt-5.14.0-503.22.1.el9_5`. Red Hat recommends to update the respective kernel and kernel-rt version to above release or later using `dnf update kernel` or `dnf update kernel-rt` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2025:0578.

### 4) `CVE-2024-53088`

#### Description

In the Linux kernel, the following vulnerability has been resolved:

    i40e: fix race condition by adding filter's intermediate sync state

Fix a race condition in the i40e driver that leads to MAC/VLAN filters
becoming corrupted and leaking. Address the issue that occurs under
heavy load when multiple threads are concurrently modifying MAC/VLAN
filters by setting mac and port VLAN. Intel can't open-source the exact code for stable reproduction now.

1. Thread T0 allocates a filter in i40e_add_filter() within `i40e_ndo_set_vf_port_vlan()`.
2. Thread T1 concurrently frees the filter in `__i40e_del_filter()` within `i40e_ndo_set_vf_mac()`.
3. Subsequently, `i40e_service_task()` calls `i40e_sync_vsi_filters()`, which refers to the already freed filter memory, causing corruption.

Reproduction steps:

1. Spawn multiple VFs.
2. Apply a concurrent heavy load by running parallel operations to change MAC addresses on the VFs and change port VLANs on the host.
3. Observe errors in dmesg:
~~~
"Error I40E_AQ_RC_ENOSPC adding RX filters on VF XX,
	please set promiscuous on manually for VF XX".
~~~

#### Statement

The fix involves implementing a new intermediate filter state, I40E_FILTER_NEW_SYNC, for the time when a filter is on a tmp_add_list. These filters cannot be deleted from the hash list directly but must be removed using the full process.

#### Solution

`CVE-2024-53088` is fixed in `kernel-5.14.0-503.22.1.el9_5` for Red Hat Enterprise Linux 9. The fix for `kernel-rt` is released in `kernel-rt-5.14.0-503.22.1.el9_5`. Red Hat recommends to update the respective kernel and kernel-rt version to above release or later using `dnf update kernel` or `dnf update kernel-rt` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2025:0578.

### 5) `CVE-2024-46713`

#### Description

In the Linux kernel, the following vulnerability has been resolved:

~~~
perf/aux: Fix AUX buffer serialization
~~~

Ole reported that event->mmap_mutex is strictly insufficient to serialize the AUX buffer, add a per RB mutex to fully serialize it.

The file(s) affected by this issue are:

~~~
kernel/events/core.c
kernel/events/internal.h
kernel/events/ring_buffer.c
~~~

#### Statement

Note that in the lock order comment the perf_event::mmap_mutex order was already wrong, that is, it nesting under mmap_lock is not new with this patch.

#### Solution

`CVE-2024-46713` is fixed in `kernel-5.14.0-503.21.1.el9_5` for Red Hat Enterprise Linux 9. The fix for `kernel-rt` is released in `kernel-rt-5.14.0-503.21.1.el9_5`. Red Hat recommends to update the respective kernel and kernel-rt version to above release or later using `dnf update kernel` or `dnf update kernel-rt` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2025:0059.

### 6) `CVE-2024-50208`

#### Description

In the Linux kernel, the following vulnerability has been resolved:

~~~
RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages
~~~

Avoid memory corruption while setting up Level-2 PBL pages for the non MR
resources when num_pages > 256K.

There will be a single PDE page address (contiguous pages in the case of >
PAGE_SIZE), but, current logic assumes multiple pages, leading to invalid
memory access after 256K PBL entries in the PDE.

#### Statement

The Linux kernel CVE team has assigned CVE-2024-50208 to this issue.

#### Solution

`CVE-2024-50208` is fixed in `kernel-5.14.0-503.21.1.el9_5` for Red Hat Enterprise Linux 9. The fix for `kernel-rt` is released in `kernel-rt-5.14.0-503.21.1.el9_5`. Red Hat recommends to update the respective kernel and kernel-rt version to above release or later using `dnf update kernel` or `dnf update kernel-rt` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2025:0059.

### 7) `CVE-2024-53122`

#### Description

A divide by zero flaw was found in the Linux kernel's Multipath TCP (MPTCP). This issue could allow a remote user to crash the system.

#### Statement

By default, the MPTCP support is disabled in RHEL. This bug is only applicable if enabled.

#### Solution

If enabled, you may disable MPTCP support. For more information please read https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/getting-started-with-multipath-tcp_configuring-and-managing-networking#preparing-rhel-to-enable-mptcp-support_getting-started-with-multipath-tcp

`CVE-2024-53122` is fixed in `kernel-5.14.0-503.21.1.el9_5` for Red Hat Enterprise Linux 9. The fix for `kernel-rt` is released in `kernel-rt-5.14.0-503.21.1.el9_5`.  Additionally Red Hat has rolled out `kpatch-patch-5_14_0-503_15_1-1-1.el9_5` for live patching. Red Hat recommends to update the respective kernel and kernel-rt version to above release or later using `dnf update kernel` or `dnf update kernel-rt` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2025:0059 and https://access.redhat.com/errata/RHSA-2025:0049

### 8) `CVE-2024-41009`

#### Description

An out-of-bounds memory access flaw was found in the Linux kernel’s BPF subsystem. This flaw allows a local user to crash the system.

#### Statement

Refer bugzilla https://bugzilla.redhat.com/show_bug.cgi?id=2298412 to understand the sequence of the crash.

#### Solution

`CVE-2024-41009` is fixed in `kernel-5.14.0-503.15.1.el9_5` for Red Hat Enterprise Linux 9. This vulnerability will not be fixed for `kernel-rt`. Red Hat recommends to update the respective kernel version to above release or later using `dnf update kernel` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:10274.

### 9) `CVE-2024-46858`

#### Description

In the Linux kernel, the following vulnerability has been resolved:

~~~
mptcp: pm: Fix uaf in __timer_delete_sync
~~~

There are two paths to access mptcp_pm_del_add_timer, result in a race
condition:

~~~
     CPU1			                        	CPU2
     ====                               ====
     net_rx_action
     napi_poll                          netlink_sendmsg
     __napi_poll                        netlink_unicast
     process_backlog                    netlink_unicast_kernel
     __netif_receive_skb                genl_rcv
     __netif_receive_skb_one_core       netlink_rcv_skb
     NF_HOOK                            genl_rcv_msg
     ip_local_deliver_finish            genl_family_rcv_msg
     ip_protocol_deliver_rcu            genl_family_rcv_msg_doit
     tcp_v4_rcv                         mptcp_pm_nl_flush_addrs_doit
     tcp_v4_do_rcv                      mptcp_nl_remove_addrs_list
     tcp_rcv_established                mptcp_pm_remove_addrs_and_subflows
     tcp_data_queue                     remove_anno_list_by_saddr
     mptcp_incoming_options             mptcp_pm_del_add_timer
     mptcp_pm_del_add_timer             kfree(entry)
~~~

In remove_anno_list_by_saddr(running on CPU2), after leaving the critical
zone protected by "pm.lock", the entry will be released, which leads to the
occurrence of uaf in the mptcp_pm_del_add_timer(running on CPU1).

Keeping a reference to add_timer inside the lock, and calling
sk_stop_timer_sync() with this reference, instead of "entry->add_timer".

Move list_del(&entry->list) to mptcp_pm_del_add_timer and inside the pm lock,
do not directly access any members of the entry outside the pm lock, which
can avoid similar "entry->x" uaf.

#### Statement

Actual only for latest version of Red Hat Enterprise Linux 9 and latest version of Red Hat Enterprise Linux 8.

The issue only affects latest Red Hat Enterprise Linux 9 and latest version of Red Hat Enterprise Linux 8 which is 8.9.

#### Solution

`CVE-2024-46858` is fixed in `kernel-5.14.0-503.14.1.el9_5` for Red Hat Enterprise Linux 9. The fix for `kernel-rt` is released in `kernel-rt-5.14.0-503.14.1.el9_5`. Red Hat recommends to update the respective kernel and kernel-rt version to above release or later using `dnf update kernel` or `dnf update kernel-rt` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2024:9605.

### 10) `CVE-2023-52490`

#### Description

A page mapping vulnerability was found in the Linux kernel. A call to the page_mapping() function during a page migration may return an incorrect file mapping and cause a system crash if another thread is simultaneously attempting to offline the target page that is being migrated.

#### Statement

Red Hat Enterprise Linux 8 is not impacted by this vulnerability.

#### Solution

`CVE-2023-52490` is fixed in `kernel-5.14.0-503.26.1.el9_5` for Red Hat Enterprise Linux 9. The fix for `kernel-rt` is released in `kernel-rt-5.14.0-503.26.1.el9_5`. Red Hat recommends to update the respective kernel and kernel-rt version to above release or later using `dnf update kernel` or `dnf update kernel-rt` command and perform a `reboot` to mitigate this vulnerability. For more details refer Red Hat Security Advisory https://access.redhat.com/errata/RHSA-2025:1659.
