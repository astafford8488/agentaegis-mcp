# AgentAegis — Access Control Policy

> **Organization:** AgentAegis · **Version:** 1.0 · **Owner:** Information Security Team
>
> **Effective:** 2026-05-04 · **Next review:** 2027-05-04 · **Frameworks:** SOC2, ISO27001

## 1. Purpose

Establish access control requirements to protect AgentAegis's information systems and data from unauthorized access.

## 2. Principles

- Least Privilege: Users receive minimum access required for their role
- Need-to-Know: Access to data granted only when required for job function
- Separation of Duties: No single individual should control all aspects of a critical process

## 3. Account Management

- All access requires formal request and management approval
- Accounts provisioned within 24 hours of approved request
- Access removed within 24 hours of employment termination
- Accounts disabled after 90 days of inactivity
- Service accounts documented and reviewed quarterly

## 4. Authentication

- Multi-factor authentication required for all accounts
- Passwords: minimum 12 characters, complexity required
- Admin accounts: hardware security keys required
- Session timeout: 15 minutes of inactivity

## 5. Access Reviews

User access reviews conducted quarterly. IT manager certify access appropriateness for their teams.

## 6. Remote Access

Access to cloud systems requires SSO via corporate identity provider. Direct credential access prohibited.

---

*Generated from `audit/policies/access_control.json` by `audit/render-policies.mjs` — do not hand-edit; re-run the script to regenerate.*
