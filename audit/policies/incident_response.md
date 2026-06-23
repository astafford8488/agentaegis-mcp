# AgentAegis — Incident Response Policy

> **Organization:** AgentAegis · **Version:** 1.0 · **Owner:** Information Security Team
>
> **Effective:** 2026-05-04 · **Next review:** 2027-05-04 · **Frameworks:** SOC2, ISO27001

## 1. Purpose

This policy establishes the framework for identifying, responding to, and recovering from information security incidents at AgentAegis. It ensures a consistent, coordinated approach to minimizing the impact of security events.

## 2. Scope

This policy applies to all employees, contractors, and third parties with access to AgentAegis's information systems. It covers all types of security incidents including but not limited to: unauthorized access, data breaches, malware infections, denial of service attacks, and insider threats.

## 3. Incident Classification

Incidents are classified by severity to ensure appropriate response:

- P1 (Critical): Active data breach, ransomware, or system compromise affecting production. Response: Immediate (within 15 minutes).
- P2 (High): Confirmed malware, unauthorized access attempt to sensitive systems. Response: Within 1 hour.
- P3 (Medium): Suspicious activity, policy violations, phishing attempts. Response: Within 4 hours.
- P4 (Low): Minor policy violations, informational security events. Response: Within 24 hours.

## 4. Roles and Responsibilities

The Incident Response Team consists of:

- Incident Commander: Leads response, makes escalation decisions
- Security Analyst: Investigates and contains the incident
- Communications Lead: Manages internal/external communications
- Legal/Compliance: Advises on regulatory obligations
- Note: In smaller organizations, one person may fill multiple roles

## 5. Response Procedures

- Detection & Identification: Validate the incident, determine scope and impact
- Containment: Isolate affected systems to prevent spread (short-term and long-term containment)
- Eradication: Remove the threat from all affected systems
- Recovery: Restore systems to normal operation, verify integrity
- Post-Incident Review: Conduct retrospective within 5 business days of resolution

## 6. Communication & Notification

AgentAegis will notify affected parties as follows:

- Internal: All P1/P2 incidents communicated to executive team within 2 hours
- Customers: Notified within 72 hours of confirmed data breach (per GDPR) or as required by applicable law
- Regulators: As required by applicable law and contractual obligations
- Law Enforcement: For incidents involving criminal activity, in coordination with legal counsel

## 7. Evidence Preservation

All incident evidence must be preserved following chain-of-custody procedures. This includes system logs, memory dumps, disk images, network captures, and communications related to the incident.

## 8. Policy Review

This policy is reviewed annually and after any P1/P2 incident. Tabletop exercises are conducted at least annually to validate response procedures.

---

*Generated from `audit/policies/incident_response.json` by `audit/render-policies.mjs` — do not hand-edit; re-run the script to regenerate.*
