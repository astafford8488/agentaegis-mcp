# AgentAegis — Business Continuity Policy

> **Organization:** AgentAegis · **Version:** 1.0 · **Owner:** Information Security Team
>
> **Effective:** 2026-05-04 · **Next review:** 2027-05-04 · **Frameworks:** SOC2, ISO27001

## 1. Purpose

Ensure AgentAegis can maintain critical business operations during and after a disruptive event.

## 2. Recovery Objectives

- RTO (Recovery Time Objective): Maximum acceptable downtime for critical systems
- RPO (Recovery Point Objective): Maximum acceptable data loss measured in time
- Critical systems RTO: 4 hours / RPO: 1 hour
- Standard systems RTO: 24 hours / RPO: 24 hours

## 3. Backup Requirements

- Critical data: Daily backups, retained 90 days minimum
- Backups stored in geographically separate location
- Backup restoration tested quarterly
- Encryption required for all backup data

## 4. Disaster Recovery

- DR plan documented and maintained for critical systems
- Annual DR test (full failover for critical systems)
- Contact tree updated quarterly
- Alternate work locations identified

## 5. Testing

BC/DR plans tested annually. Tabletop exercise minimum; full test recommended.

---

*Generated from `audit/policies/business_continuity.json` by `audit/render-policies.mjs` — do not hand-edit; re-run the script to regenerate.*
