import { z } from "zod";

export const policyGenerateSchema = z.object({
  policy_type: z.enum([
    "incident_response", "acceptable_use", "data_classification",
    "access_control", "change_management", "vendor_management",
    "business_continuity", "encryption", "remote_work", "byod",
  ]),
  organization_name: z.string(),
  industry: z.string(),
  employee_count: z.number(),
  frameworks: z.array(z.string()),
  customizations: z.object({
    data_types: z.array(z.string()).optional(),
    remote_workforce: z.boolean().optional(),
    byod_allowed: z.boolean().optional(),
    cloud_first: z.boolean().optional(),
  }).optional(),
});

export type PolicyGenerateInput = z.infer<typeof policyGenerateSchema>;

export async function policyGenerate(input: PolicyGenerateInput) {
  const { policy_type, organization_name, industry, employee_count, frameworks, customizations } = input;

  const today = new Date().toISOString().split("T")[0];
  const reviewDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
  const size = employee_count < 50 ? "small" : employee_count < 250 ? "medium" : "large";

  const policyTemplates: Record<string, () => object> = {
    incident_response: () => generateIncidentResponsePolicy(organization_name, size, industry),
    acceptable_use: () => generateAcceptableUsePolicy(organization_name, size, customizations),
    data_classification: () => generateDataClassificationPolicy(organization_name, industry, customizations),
    access_control: () => generateAccessControlPolicy(organization_name, size, customizations),
    change_management: () => generateChangeManagementPolicy(organization_name, size),
    vendor_management: () => generateVendorManagementPolicy(organization_name, industry),
    business_continuity: () => generateBusinessContinuityPolicy(organization_name, size, industry),
    encryption: () => generateEncryptionPolicy(organization_name, industry),
    remote_work: () => generateRemoteWorkPolicy(organization_name, size),
    byod: () => generateBYODPolicy(organization_name, size),
  };

  const policyContent = policyTemplates[policy_type]();

  return {
    metadata: {
      policy_type,
      organization: organization_name,
      version: "1.0",
      effective_date: today,
      next_review_date: reviewDate,
      owner: "Information Security Team",
      applicable_frameworks: frameworks,
    },
    ...policyContent,
  };
}

function generateIncidentResponsePolicy(org: string, size: string, industry: string) {
  return {
    title: `${org} — Incident Response Policy`,
    sections: [
      {
        heading: "1. Purpose",
        content: `This policy establishes the framework for identifying, responding to, and recovering from information security incidents at ${org}. It ensures a consistent, coordinated approach to minimizing the impact of security events.`,
      },
      {
        heading: "2. Scope",
        content: `This policy applies to all employees, contractors, and third parties with access to ${org}'s information systems. It covers all types of security incidents including but not limited to: unauthorized access, data breaches, malware infections, denial of service attacks, and insider threats.`,
      },
      {
        heading: "3. Incident Classification",
        content: "Incidents are classified by severity to ensure appropriate response:",
        sub_items: [
          "P1 (Critical): Active data breach, ransomware, or system compromise affecting production. Response: Immediate (within 15 minutes).",
          "P2 (High): Confirmed malware, unauthorized access attempt to sensitive systems. Response: Within 1 hour.",
          "P3 (Medium): Suspicious activity, policy violations, phishing attempts. Response: Within 4 hours.",
          "P4 (Low): Minor policy violations, informational security events. Response: Within 24 hours.",
        ],
      },
      {
        heading: "4. Roles and Responsibilities",
        content: "The Incident Response Team consists of:",
        sub_items: [
          "Incident Commander: Leads response, makes escalation decisions",
          "Security Analyst: Investigates and contains the incident",
          "Communications Lead: Manages internal/external communications",
          "Legal/Compliance: Advises on regulatory obligations",
          size === "small" ? "Note: In smaller organizations, one person may fill multiple roles" : "Operations Lead: Coordinates system recovery",
        ],
      },
      {
        heading: "5. Response Procedures",
        sub_items: [
          "Detection & Identification: Validate the incident, determine scope and impact",
          "Containment: Isolate affected systems to prevent spread (short-term and long-term containment)",
          "Eradication: Remove the threat from all affected systems",
          "Recovery: Restore systems to normal operation, verify integrity",
          "Post-Incident Review: Conduct retrospective within 5 business days of resolution",
        ],
      },
      {
        heading: "6. Communication & Notification",
        content: `${org} will notify affected parties as follows:`,
        sub_items: [
          "Internal: All P1/P2 incidents communicated to executive team within 2 hours",
          "Customers: Notified within 72 hours of confirmed data breach (per GDPR) or as required by applicable law",
          industry === "healthcare" ? "HHS: HIPAA breach notification within 60 days for breaches affecting 500+ individuals" : "Regulators: As required by applicable law and contractual obligations",
          "Law Enforcement: For incidents involving criminal activity, in coordination with legal counsel",
        ],
      },
      {
        heading: "7. Evidence Preservation",
        content: "All incident evidence must be preserved following chain-of-custody procedures. This includes system logs, memory dumps, disk images, network captures, and communications related to the incident.",
      },
      {
        heading: "8. Policy Review",
        content: "This policy is reviewed annually and after any P1/P2 incident. Tabletop exercises are conducted at least annually to validate response procedures.",
      },
    ],
  };
}

function generateAcceptableUsePolicy(org: string, size: string, customizations?: PolicyGenerateInput["customizations"]) {
  return {
    title: `${org} — Acceptable Use Policy`,
    sections: [
      { heading: "1. Purpose", content: `This policy defines acceptable use of ${org}'s information technology resources to protect the organization, its employees, and its customers.` },
      { heading: "2. Scope", content: `Applies to all employees, contractors, and authorized users of ${org}'s IT resources including but not limited to computers, networks, email, internet access, and cloud services.` },
      { heading: "3. General Use", sub_items: ["IT resources are provided primarily for business purposes", "Limited personal use is permitted if it does not interfere with work duties or violate this policy", "Users are responsible for the security of their accounts and devices"] },
      { heading: "4. Prohibited Activities", sub_items: ["Accessing, downloading, or distributing illegal or inappropriate content", "Unauthorized access to systems or data", "Installing unauthorized software", "Sharing credentials or access", "Circumventing security controls", "Using company resources for personal commercial activities", "Sending unsolicited bulk communications"] },
      { heading: "5. Email & Communications", sub_items: ["Use professional language in all business communications", "Do not open suspicious attachments or click unknown links", "Report phishing attempts immediately to IT/Security", "Sensitive data must not be sent via unencrypted email"] },
      { heading: "6. Remote Work", content: customizations?.remote_workforce ? "Remote work is supported. Additional security measures apply: use company VPN, lock screens when away, ensure home network is secured, do not use public WiFi without VPN." : "Remote access must be approved by management and secured via VPN." },
      { heading: "7. Enforcement", content: "Violations may result in disciplinary action up to and including termination and legal action." },
    ],
  };
}

function generateDataClassificationPolicy(org: string, industry: string, customizations?: PolicyGenerateInput["customizations"]) {
  const dataTypes = customizations?.data_types || ["customer PII", "financial records", "intellectual property"];
  return {
    title: `${org} — Data Classification Policy`,
    sections: [
      { heading: "1. Purpose", content: `This policy establishes a data classification framework to ensure ${org} protects information assets according to their sensitivity and value.` },
      { heading: "2. Classification Levels", sub_items: [
        "PUBLIC: Information intended for public consumption. No restrictions on sharing.",
        "INTERNAL: Business information not intended for public release. Share only with authorized employees.",
        "CONFIDENTIAL: Sensitive business information. Access on need-to-know basis. Includes: " + dataTypes.join(", "),
        "RESTRICTED: Highest sensitivity. Includes credentials, encryption keys, and regulated data. Strict access controls required.",
      ]},
      { heading: "3. Handling Requirements", sub_items: [
        "RESTRICTED: Encrypted at rest and in transit, access logged, no external sharing without legal approval",
        "CONFIDENTIAL: Encrypted in transit, access controlled, sharing requires management approval",
        "INTERNAL: Reasonable access controls, no public sharing",
        "PUBLIC: No special handling required",
      ]},
      { heading: "4. Data Owners", content: "Each data asset must have a designated owner responsible for classification, access decisions, and periodic review." },
      { heading: "5. Retention & Disposal", content: "Data must be retained per legal/regulatory requirements and securely disposed of when no longer needed. Secure disposal means cryptographic erasure or physical destruction." },
    ],
  };
}

function generateAccessControlPolicy(org: string, size: string, customizations?: PolicyGenerateInput["customizations"]) {
  return {
    title: `${org} — Access Control Policy`,
    sections: [
      { heading: "1. Purpose", content: `Establish access control requirements to protect ${org}'s information systems and data from unauthorized access.` },
      { heading: "2. Principles", sub_items: ["Least Privilege: Users receive minimum access required for their role", "Need-to-Know: Access to data granted only when required for job function", "Separation of Duties: No single individual should control all aspects of a critical process"] },
      { heading: "3. Account Management", sub_items: ["All access requires formal request and management approval", "Accounts provisioned within 24 hours of approved request", "Access removed within 24 hours of employment termination", "Accounts disabled after 90 days of inactivity", "Service accounts documented and reviewed quarterly"] },
      { heading: "4. Authentication", sub_items: ["Multi-factor authentication required for all accounts", "Passwords: minimum 12 characters, complexity required", "Admin accounts: hardware security keys required", "Session timeout: 15 minutes of inactivity"] },
      { heading: "5. Access Reviews", content: `User access reviews conducted quarterly. ${size === "small" ? "IT manager" : "Department managers"} certify access appropriateness for their teams.` },
      { heading: "6. Remote Access", content: customizations?.cloud_first ? "Access to cloud systems requires SSO via corporate identity provider. Direct credential access prohibited." : "VPN required for remote access to internal systems." },
    ],
  };
}

function generateChangeManagementPolicy(org: string, size: string) {
  return {
    title: `${org} — Change Management Policy`,
    sections: [
      { heading: "1. Purpose", content: `Establish a controlled process for managing changes to ${org}'s information systems to minimize risk and disruption.` },
      { heading: "2. Change Categories", sub_items: ["Standard: Pre-approved, low-risk changes (e.g., minor patches, config updates)", "Normal: Requires review and approval before implementation", "Emergency: Critical changes needed to restore service or address security threats"] },
      { heading: "3. Change Process", sub_items: ["Request: Document change, reason, risk assessment, rollback plan", "Review: Peer review of technical implementation", "Approve: Change Advisory Board (CAB) approval for Normal changes", "Implement: Execute during approved maintenance window", "Verify: Confirm change is functioning as expected", "Close: Document outcome and lessons learned"] },
      { heading: "4. Approval Matrix", sub_items: [size === "small" ? "Standard: Auto-approved with peer review" : "Standard: Team lead approval", "Normal: CAB approval (meets weekly)", "Emergency: Single approver from on-call management, retroactive CAB review within 48 hours"] },
      { heading: "5. Code Changes", sub_items: ["All code changes require version control (Git)", "Pull/merge requests required with at least one reviewer", "Automated testing must pass before merge", "Production deployments require explicit approval"] },
    ],
  };
}

function generateVendorManagementPolicy(org: string, industry: string) {
  return {
    title: `${org} — Vendor Management Policy`,
    sections: [
      { heading: "1. Purpose", content: `Establish requirements for assessing and managing the security risks associated with ${org}'s third-party vendors and service providers.` },
      { heading: "2. Vendor Classification", sub_items: ["Critical: Vendors with access to sensitive data or critical systems", "Standard: Vendors with limited access or non-sensitive roles", "Low: Vendors with no data access or system connectivity"] },
      { heading: "3. Assessment Requirements", sub_items: ["Critical vendors: Annual security assessment, SOC 2 report review, contractual security requirements", "Standard vendors: Security questionnaire review, contractual data protection terms", "Low vendors: Basic due diligence only"] },
      { heading: "4. Contractual Requirements", sub_items: ["Data processing agreements where applicable", "Security incident notification requirements (24-48 hours)", "Right to audit clause", "Data return/destruction upon contract termination", industry === "healthcare" ? "BAA (Business Associate Agreement) for PHI access" : "Compliance with applicable regulations"] },
      { heading: "5. Ongoing Monitoring", content: "Critical vendors reviewed annually. Security incidents involving vendors trigger immediate reassessment." },
    ],
  };
}

function generateBusinessContinuityPolicy(org: string, size: string, industry: string) {
  return {
    title: `${org} — Business Continuity Policy`,
    sections: [
      { heading: "1. Purpose", content: `Ensure ${org} can maintain critical business operations during and after a disruptive event.` },
      { heading: "2. Recovery Objectives", sub_items: ["RTO (Recovery Time Objective): Maximum acceptable downtime for critical systems", "RPO (Recovery Point Objective): Maximum acceptable data loss measured in time", "Critical systems RTO: 4 hours / RPO: 1 hour", "Standard systems RTO: 24 hours / RPO: 24 hours"] },
      { heading: "3. Backup Requirements", sub_items: ["Critical data: Daily backups, retained 90 days minimum", "Backups stored in geographically separate location", "Backup restoration tested quarterly", "Encryption required for all backup data"] },
      { heading: "4. Disaster Recovery", sub_items: ["DR plan documented and maintained for critical systems", "Annual DR test (full failover for critical systems)", "Contact tree updated quarterly", "Alternate work locations identified"] },
      { heading: "5. Testing", content: `BC/DR plans tested annually. ${size === "large" ? "Full failover test required." : "Tabletop exercise minimum; full test recommended."}` },
    ],
  };
}

function generateEncryptionPolicy(org: string, industry: string) {
  return {
    title: `${org} — Encryption Policy`,
    sections: [
      { heading: "1. Purpose", content: `Define encryption requirements to protect ${org}'s data confidentiality and integrity.` },
      { heading: "2. Data at Rest", sub_items: ["RESTRICTED and CONFIDENTIAL data must be encrypted at rest", "Minimum: AES-256 for symmetric encryption", "Full disk encryption required on all endpoints", "Database encryption (TDE or field-level) for sensitive data"] },
      { heading: "3. Data in Transit", sub_items: ["TLS 1.2 minimum for all network communications (TLS 1.3 preferred)", "Internal service-to-service: mTLS where feasible", "VPN for remote access to internal networks", "Email encryption for CONFIDENTIAL/RESTRICTED data"] },
      { heading: "4. Key Management", sub_items: ["Encryption keys stored in dedicated key management system (KMS)", "Key rotation: annually minimum, immediately if compromised", "Key access logged and audited", "Separation of duties between key custodians"] },
      { heading: "5. Prohibited", sub_items: ["No custom/proprietary encryption algorithms", "No deprecated algorithms (DES, 3DES, RC4, MD5 for integrity)", "No hardcoded keys in source code", "No key transmission via unencrypted channels"] },
    ],
  };
}

function generateRemoteWorkPolicy(org: string, size: string) {
  return {
    title: `${org} — Remote Work Security Policy`,
    sections: [
      { heading: "1. Purpose", content: `Define security requirements for ${org} employees working remotely.` },
      { heading: "2. Network Security", sub_items: ["VPN required for accessing internal resources", "Home WiFi must use WPA2/WPA3 encryption", "Public WiFi prohibited for work without VPN", "Split tunneling disabled on company devices"] },
      { heading: "3. Device Security", sub_items: ["Company-managed devices required for accessing company data", "Full disk encryption enabled", "Automatic screen lock after 5 minutes", "Current antivirus/EDR agent running", "Automatic OS and application updates enabled"] },
      { heading: "4. Physical Security", sub_items: ["Lock screen when stepping away", "No work on screens visible to others in public", "Sensitive documents shredded, not recycled", "Secure home office space recommended for calls with sensitive content"] },
      { heading: "5. Data Handling", sub_items: ["No company data stored on personal devices", "Cloud storage via approved services only", "Printing CONFIDENTIAL/RESTRICTED documents requires approval", "Virtual desktop recommended for sensitive operations"] },
    ],
  };
}

function generateBYODPolicy(org: string, size: string) {
  return {
    title: `${org} — Bring Your Own Device (BYOD) Policy`,
    sections: [
      { heading: "1. Purpose", content: `Define requirements and restrictions for using personal devices to access ${org}'s resources.` },
      { heading: "2. Eligible Devices", sub_items: ["Smartphones (iOS 16+, Android 13+)", "Tablets (same OS requirements)", "Laptops: case-by-case with IT approval", "Minimum security patch level: within 30 days of latest"] },
      { heading: "3. Required Security Controls", sub_items: ["Device passcode/biometric lock enabled", "Device encryption enabled", "Remote wipe capability (MDM enrollment)", "No jailbroken/rooted devices", "Automatic OS updates enabled"] },
      { heading: "4. Access Limitations", sub_items: ["BYOD access limited to email, calendar, and approved cloud apps", "No access to RESTRICTED data from personal devices", "Company reserves right to remote wipe company data (not personal data)", "VPN required for intranet access"] },
      { heading: "5. Employee Responsibilities", sub_items: ["Report lost/stolen devices immediately", "Remove company data upon separation", "Allow IT to verify compliance", "Accept that company may remotely wipe company data container"] },
    ],
  };
}
