# Security Review: unilag.edu.ng

**Review date:** 2026-10-12  
**Scope:** Publicly accessible responses from `https://unilag.edu.ng/` and the standard `/.well-known/security.txt` path.

## Summary

No confirmed exploitable vulnerabilities were identified in this passive review. The observations below are low-severity hardening opportunities, not evidence that the site is exploitable.

## Findings

| # | Severity | URL | Observation | Confidence |
|---|----------|-----|-------------|------------|
| 1 | ⚪ LOW | `https://unilag.edu.ng/` | The enforced Content Security Policy specifies `frame-ancestors 'self'` but no other CSP restrictions. Consider a tailored policy, after testing site compatibility. | 8/10 |
| 2 | ⚪ LOW | `https://unilag.edu.ng/` | The response discloses the server banner `Apache/2.4.52 (Ubuntu)`. Suppressing detailed version information reduces unnecessary information disclosure; the banner alone does not establish that the server is vulnerable. | 9/10 |
| 3 | ⚪ LOW | `https://unilag.edu.ng/.well-known/security.txt` | The standard security contact path returned `404 Not Found`. Consider publishing a `security.txt` with a vulnerability-reporting contact. | 9/10 |

## Method and limitations

The review was limited to passive inspection of publicly accessible responses and ordinary GET requests. It did not authenticate, submit forms, fuzz, exploit, bypass controls, scan ports, or access non-public data. This is not a comprehensive penetration test, and no claims are made about application behavior or assets outside the stated scope.
