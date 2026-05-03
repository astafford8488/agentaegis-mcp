import { z } from "zod";
import { lookupCVE, checkKEV } from "../../apis/nvd.js";

export const cveLookupSchema = z.object({
  cve_id: z.string().regex(/^CVE-\d{4}-\d{4,}$/, "Must be a valid CVE ID (e.g., CVE-2024-1234)"),
});

export type CVELookupInput = z.infer<typeof cveLookupSchema>;

export async function cveLookup(input: CVELookupInput) {
  const { cve_id } = input;

  const cveDetail = await lookupCVE(cve_id);
  if (!cveDetail) {
    return { error: `CVE ${cve_id} not found in NVD database`, cve_id };
  }

  const isInKEV = await checkKEV(cve_id);

  return {
    cve_id: cveDetail.id,
    description: cveDetail.description,
    published: cveDetail.published,
    last_modified: cveDetail.last_modified,
    cvss_v3: cveDetail.cvss_v3,
    severity: cveDetail.cvss_v3
      ? cveDetail.cvss_v3.score >= 9.0 ? "CRITICAL"
        : cveDetail.cvss_v3.score >= 7.0 ? "HIGH"
        : cveDetail.cvss_v3.score >= 4.0 ? "MEDIUM"
        : "LOW"
      : "UNKNOWN",
    cwe_classifications: cveDetail.cwe,
    affected_products: cveDetail.affected_products.slice(0, 20),
    references: cveDetail.references.slice(0, 10),
    known_exploited: isInKEV,
    kev_note: isInKEV
      ? "⚠️ This CVE is in CISA's Known Exploited Vulnerabilities catalog — active exploitation confirmed. Patch immediately."
      : null,
    patch_available: cveDetail.references.some((r) =>
      r.tags.includes("Patch") || r.tags.includes("Vendor Advisory")
    ),
    patch_references: cveDetail.references.filter((r) =>
      r.tags.includes("Patch") || r.tags.includes("Vendor Advisory")
    ),
  };
}
