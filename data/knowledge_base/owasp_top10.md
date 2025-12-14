# OWASP Top 10 Security Risks

## A01:2021 – Broken Access Control
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.

## A02:2021 – Cryptographic Failures
Previously known as "Sensitive Data Exposure," this category focuses on failures related to cryptography which often leads to sensitive data exposure or system compromise.

## A03:2021 – Injection
Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

## A04:2021 – Insecure Design
Insecure design is a broad category representing different weaknesses, expressed as "missing or ineffective control design." Insecure design is not the source of all other Top 10 risk categories.

## A05:2021 – Security Misconfiguration
Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.

## A06:2021 – Vulnerable and Outdated Components
Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.

## A07:2021 – Identification and Authentication Failures
Previously known as "Broken Authentication," this category is now more clearly focused on failures related to identification and authentication.

## A08:2021 – Software and Data Integrity Failures
Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).

## A09:2021 – Security Logging and Monitoring Failures
This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected.

## A10:2021 – Server-Side Request Forgery (SSRF)
SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.

