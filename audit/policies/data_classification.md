# AgentAegis — Data Classification Policy

> **Organization:** AgentAegis · **Version:** 1.0 · **Owner:** Information Security Team
>
> **Effective:** 2026-05-04 · **Next review:** 2027-05-04 · **Frameworks:** SOC2, ISO27001

## 1. Purpose

This policy establishes a data classification framework to ensure AgentAegis protects information assets according to their sensitivity and value.

## 2. Classification Levels

- PUBLIC: Information intended for public consumption. No restrictions on sharing.
- INTERNAL: Business information not intended for public release. Share only with authorized employees.
- CONFIDENTIAL: Sensitive business information. Access on need-to-know basis. Includes: customer PII, financial records, intellectual property
- RESTRICTED: Highest sensitivity. Includes credentials, encryption keys, and regulated data. Strict access controls required.

## 3. Handling Requirements

- RESTRICTED: Encrypted at rest and in transit, access logged, no external sharing without legal approval
- CONFIDENTIAL: Encrypted in transit, access controlled, sharing requires management approval
- INTERNAL: Reasonable access controls, no public sharing
- PUBLIC: No special handling required

## 4. Data Owners

Each data asset must have a designated owner responsible for classification, access decisions, and periodic review.

## 5. Retention & Disposal

Data must be retained per legal/regulatory requirements and securely disposed of when no longer needed. Secure disposal means cryptographic erasure or physical destruction.

---

*Generated from `audit/policies/data_classification.json` by `audit/render-policies.mjs` — do not hand-edit; re-run the script to regenerate.*
