# AgentAegis — Change Management Policy

> **Organization:** AgentAegis · **Version:** 1.0 · **Owner:** Information Security Team
>
> **Effective:** 2026-05-04 · **Next review:** 2027-05-04 · **Frameworks:** SOC2, ISO27001

## 1. Purpose

Establish a controlled process for managing changes to AgentAegis's information systems to minimize risk and disruption.

## 2. Change Categories

- Standard: Pre-approved, low-risk changes (e.g., minor patches, config updates)
- Normal: Requires review and approval before implementation
- Emergency: Critical changes needed to restore service or address security threats

## 3. Change Process

- Request: Document change, reason, risk assessment, rollback plan
- Review: Peer review of technical implementation
- Approve: Change Advisory Board (CAB) approval for Normal changes
- Implement: Execute during approved maintenance window
- Verify: Confirm change is functioning as expected
- Close: Document outcome and lessons learned

## 4. Approval Matrix

- Standard: Auto-approved with peer review
- Normal: CAB approval (meets weekly)
- Emergency: Single approver from on-call management, retroactive CAB review within 48 hours

## 5. Code Changes

- All code changes require version control (Git)
- Pull/merge requests required with at least one reviewer
- Automated testing must pass before merge
- Production deployments require explicit approval

---

*Generated from `audit/policies/change_management.json` by `audit/render-policies.mjs` — do not hand-edit; re-run the script to regenerate.*
