import { z } from "zod";
import { checkIP } from "../../apis/abuseipdb.js";
import { lookupIndicator } from "../../apis/virustotal.js";
import type { IncidentClassification } from "../../types/security.js";

export const incidentTriageSchema = z.object({
  incident_description: z.string(),
  indicators: z.object({
    suspicious_ips: z.array(z.string()).optional(),
    suspicious_domains: z.array(z.string()).optional(),
    suspicious_hashes: z.array(z.string()).optional(),
    affected_systems: z.array(z.string()).optional(),
    affected_accounts: z.array(z.string()).optional(),
    log_snippets: z.array(z.string()).optional(),
  }),
  environment_context: z.object({
    has_edr: z.boolean(),
    has_siem: z.boolean(),
    has_backups: z.boolean(),
    has_incident_response_plan: z.boolean(),
  }).optional(),
});

export type IncidentTriageInput = z.infer<typeof incidentTriageSchema>;

export async function incidentTriage(input: IncidentTriageInput) {
  const { incident_description, indicators, environment_context } = input;

  // Classify incident type from description and indicators
  const classification = classifyIncident(incident_description, indicators);

  // Enrich indicators with threat intel
  const enrichment = await enrichIndicators(indicators);

  // Generate response plan
  const responsePlan = generateResponsePlan(classification, environment_context, indicators);

  return {
    classification,
    indicator_enrichment: enrichment,
    response_plan: responsePlan,
    communication_templates: generateCommTemplates(classification, indicators),
  };
}

function classifyIncident(
  description: string,
  indicators: IncidentTriageInput["indicators"]
): IncidentClassification {
  const desc = description.toLowerCase();
  let type: IncidentClassification["type"] = "unknown";
  let severity: IncidentClassification["severity"] = "P3";
  let confidence = 0.5;

  // Keyword-based classification
  if (desc.includes("ransom") || desc.includes("encrypted files") || desc.includes(".encrypted")) {
    type = "ransomware"; severity = "P1"; confidence = 0.9;
  } else if (desc.includes("phish") || desc.includes("credential harvest") || desc.includes("fake login")) {
    type = "phishing"; severity = "P3"; confidence = 0.8;
  } else if (desc.includes("malware") || desc.includes("trojan") || desc.includes("virus") || indicators.suspicious_hashes?.length) {
    type = "malware"; severity = "P2"; confidence = 0.7;
  } else if (desc.includes("brute force") || desc.includes("credential stuff") || desc.includes("multiple failed login")) {
    type = "credential_stuffing"; severity = "P2"; confidence = 0.8;
  } else if (desc.includes("insider") || desc.includes("unauthorized copy") || desc.includes("employee")) {
    type = "insider_threat"; severity = "P2"; confidence = 0.6;
  } else if (desc.includes("exfil") || desc.includes("data leak") || desc.includes("data breach")) {
    type = "data_exfil"; severity = "P1"; confidence = 0.7;
  } else if (desc.includes("ddos") || desc.includes("denial of service") || desc.includes("traffic spike")) {
    type = "ddos"; severity = "P2"; confidence = 0.8;
  } else if (desc.includes("unauthorized access") || indicators.suspicious_ips?.length) {
    type = "credential_stuffing"; severity = "P2"; confidence = 0.5;
  }

  // Escalate severity if many systems/accounts affected
  if ((indicators.affected_systems?.length || 0) > 5) severity = "P1";
  if ((indicators.affected_accounts?.length || 0) > 10) severity = "P1";

  return {
    type,
    severity,
    confidence,
    containment_actions: getContainmentActions(type),
    investigation_steps: getInvestigationSteps(type),
    evidence_checklist: getEvidenceChecklist(type),
    communication_templates: {},
    escalation_criteria: getEscalationCriteria(severity),
  };
}

function getContainmentActions(type: IncidentClassification["type"]): string[] {
  const common = ["Isolate affected systems from network", "Preserve forensic evidence before remediation"];
  const specific: Record<string, string[]> = {
    ransomware: ["Disconnect affected systems immediately (do NOT power off)", "Disable network shares", "Identify and isolate patient zero", "Do NOT pay ransom without legal consultation", "Check backup integrity before restoration"],
    phishing: ["Reset credentials of affected accounts", "Block sender domain/IP at email gateway", "Search for other recipients of same campaign", "Revoke any OAuth tokens granted"],
    malware: ["Quarantine affected endpoints", "Block C2 domains/IPs at firewall", "Run EDR scan across all endpoints", "Check for lateral movement"],
    credential_stuffing: ["Force password reset on affected accounts", "Enable/enforce MFA", "Block attacking IPs at WAF/firewall", "Review access logs for successful compromises"],
    insider_threat: ["Restrict suspect's access immediately", "Preserve email and file access logs", "Engage HR and legal", "Do not alert suspect until instructed by legal"],
    data_exfil: ["Block outbound connections to identified destinations", "Identify scope of data accessed", "Preserve DLP logs", "Engage legal for breach notification assessment"],
    ddos: ["Engage CDN/DDoS protection", "Rate limit at load balancer", "Block attacking IP ranges", "Scale infrastructure if possible"],
    unknown: ["Gather more information to classify", "Monitor affected systems closely"],
  };
  return [...(specific[type] || specific.unknown), ...common];
}

function getInvestigationSteps(type: IncidentClassification["type"]): string[] {
  return [
    "Establish timeline: when did the incident start?",
    "Identify initial access vector",
    "Determine scope: how many systems/users affected?",
    "Check for indicators of lateral movement",
    "Review authentication logs for anomalies",
    "Correlate with any recent changes or deployments",
    "Check if any data was accessed or exfiltrated",
    "Identify root cause",
  ];
}

function getEvidenceChecklist(type: IncidentClassification["type"]): string[] {
  return [
    "System logs (auth, application, network)",
    "Memory dumps of affected systems",
    "Network traffic captures",
    "Email headers and attachments (if phishing)",
    "File system artifacts (modified files, timestamps)",
    "Screenshots of ransom notes or indicators",
    "User activity logs",
    "Firewall and IDS/IPS logs",
  ];
}

function getEscalationCriteria(severity: IncidentClassification["severity"]): string[] {
  if (severity === "P1") {
    return [
      "Notify executive team immediately",
      "Engage external incident response firm if needed",
      "Prepare for regulatory notification (72-hour clock may start)",
      "Coordinate with legal counsel",
    ];
  }
  return [
    "Escalate to P1 if scope expands",
    "Escalate if data exfiltration confirmed",
    "Escalate if unable to contain within 4 hours",
  ];
}

async function enrichIndicators(indicators: IncidentTriageInput["indicators"]) {
  const results: Record<string, unknown> = {};

  if (indicators.suspicious_ips?.length) {
    results.ip_reputation = [];
    for (const ip of indicators.suspicious_ips.slice(0, 5)) {
      try {
        const result = await checkIP(ip);
        (results.ip_reputation as any[]).push(result);
      } catch {
        (results.ip_reputation as any[]).push({ ip, error: "Lookup failed" });
      }
    }
  }

  if (indicators.suspicious_hashes?.length) {
    results.hash_analysis = [];
    for (const hash of indicators.suspicious_hashes.slice(0, 3)) {
      try {
        const hashType = hash.length === 32 ? "hash_md5" : hash.length === 40 ? "hash_sha1" : "hash_sha256";
        const result = await lookupIndicator(hash, hashType);
        (results.hash_analysis as any[]).push(result);
      } catch {
        (results.hash_analysis as any[]).push({ hash, error: "Lookup failed" });
      }
    }
  }

  return results;
}

function generateResponsePlan(
  classification: IncidentClassification,
  context?: IncidentTriageInput["environment_context"],
  indicators?: IncidentTriageInput["indicators"]
) {
  return {
    immediate: classification.containment_actions.slice(0, 3),
    short_term: classification.investigation_steps.slice(0, 4),
    evidence: classification.evidence_checklist,
    tools_needed: context ? [
      !context.has_edr ? "Deploy EDR solution for endpoint visibility" : null,
      !context.has_siem ? "Set up log aggregation for investigation" : null,
      !context.has_backups ? "CRITICAL: Establish backup solution immediately" : null,
    ].filter(Boolean) : [],
    recovery_notes: context?.has_backups
      ? "Backups available — validate integrity before restoration"
      : "No backups confirmed — recovery may require rebuilding affected systems",
  };
}

function generateCommTemplates(classification: IncidentClassification, indicators: IncidentTriageInput["indicators"]) {
  return {
    internal_notification: `[${classification.severity}] Security incident detected — ${classification.type}. ${(indicators.affected_systems?.length || 0)} systems affected. Incident response team engaged. Updates to follow.`,
    customer_notification: classification.severity === "P1"
      ? `We are investigating a security event that may affect your data. We are taking immediate steps to contain the situation and will provide updates within 24 hours.`
      : null,
    executive_brief: `${classification.severity} security incident: ${classification.type}. Confidence: ${Math.round(classification.confidence * 100)}%. Immediate containment actions underway.`,
  };
}
