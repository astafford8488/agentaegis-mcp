# AgentAegis — Encryption Policy

> **Organization:** AgentAegis · **Version:** 1.0 · **Owner:** Information Security Team
>
> **Effective:** 2026-05-04 · **Next review:** 2027-05-04 · **Frameworks:** SOC2, ISO27001

## 1. Purpose

Define encryption requirements to protect AgentAegis's data confidentiality and integrity.

## 2. Data at Rest

- RESTRICTED and CONFIDENTIAL data must be encrypted at rest
- Minimum: AES-256 for symmetric encryption
- Full disk encryption required on all endpoints
- Database encryption (TDE or field-level) for sensitive data

## 3. Data in Transit

- TLS 1.2 minimum for all network communications (TLS 1.3 preferred)
- Internal service-to-service: mTLS where feasible
- VPN for remote access to internal networks
- Email encryption for CONFIDENTIAL/RESTRICTED data

## 4. Key Management

- Encryption keys stored in dedicated key management system (KMS)
- Key rotation: annually minimum, immediately if compromised
- Key access logged and audited
- Separation of duties between key custodians

## 5. Prohibited

- No custom/proprietary encryption algorithms
- No deprecated algorithms (DES, 3DES, RC4, MD5 for integrity)
- No hardcoded keys in source code
- No key transmission via unencrypted channels

---

*Generated from `audit/policies/encryption.json` by `audit/render-policies.mjs` — do not hand-edit; re-run the script to regenerate.*
