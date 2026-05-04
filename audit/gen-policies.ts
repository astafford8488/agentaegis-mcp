import { policyGenerate } from "../src/tools/compliance/policyGenerate.js";
import * as fs from "fs";
import * as path from "path";

const types = [
  "incident_response",
  "access_control",
  "encryption",
  "vendor_management",
  "data_classification",
  "change_management",
  "remote_work",
  "business_continuity",
] as const;

const outDir = path.join(import.meta.dirname || ".", "policies");
fs.mkdirSync(outDir, { recursive: true });

for (const t of types) {
  const result = await policyGenerate({
    policy_type: t,
    organization_name: "AgentAegis",
    industry: "fintech",
    employee_count: 1,
    frameworks: ["soc2", "iso27001"],
    customizations: { remote_workforce: true, cloud_first: true },
  });
  fs.writeFileSync(path.join(outDir, t + ".json"), JSON.stringify(result, null, 2));
  console.log("Generated:", t, "|", result.title);
}
