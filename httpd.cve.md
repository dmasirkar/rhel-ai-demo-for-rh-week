## The httpd in Red Hat Enterprise Linux 9 (RHEL) stands for HyperText Transfer Daemon, commonly known as Apache HTTP Server. Apache HTTP Server is an open-source web server software that powers many of the world's websites.The Red Hat Enterprise Linux 9 provides httpd-2.4.62 version of the Apache HTTP Server.

## This document provides a vulnerability and CVE related information about httpd package in Red Hat Enterprise Linux 9.

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

For more details refer Red Hat Security Advisory [text](https://access.redhat.com/errata/RHSA-2024:9306)

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