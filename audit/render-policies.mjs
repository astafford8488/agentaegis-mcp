// Render the generated policy JSON (audit/policies/*.json) into committable,
// human-readable markdown (audit/policies/*.md). Re-run after regenerating the
// JSON via gen-policies.ts.  Usage:  node audit/render-policies.mjs

import * as fs from "fs";
import * as path from "path";

const dir = path.join(import.meta.dirname, "policies");

function render(p, srcFile) {
  const m = p.metadata || {};
  const lines = [`# ${p.title || m.policy_type}`, ""];
  lines.push(
    `> **Organization:** ${m.organization ?? "—"} · **Version:** ${m.version ?? "—"} · **Owner:** ${m.owner ?? "—"}`,
    `>`,
    `> **Effective:** ${m.effective_date ?? "—"} · **Next review:** ${m.next_review_date ?? "—"} · **Frameworks:** ${(m.applicable_frameworks || []).map((f) => String(f).toUpperCase()).join(", ") || "—"}`,
    "",
  );
  for (const s of p.sections || []) {
    lines.push(`## ${s.heading}`, "");
    if (s.content) lines.push(s.content, "");
    if (Array.isArray(s.sub_items)) {
      for (const it of s.sub_items) lines.push(`- ${it}`);
      lines.push("");
    }
  }
  lines.push(
    "---",
    "",
    `*Generated from \`audit/policies/${srcFile}\` by \`audit/render-policies.mjs\` — do not hand-edit; re-run the script to regenerate.*`,
    "",
  );
  return lines.join("\n");
}

const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
let n = 0;
for (const f of files) {
  const p = JSON.parse(fs.readFileSync(path.join(dir, f), "utf-8"));
  const out = path.join(dir, f.replace(/\.json$/, ".md"));
  fs.writeFileSync(out, render(p, f), "utf-8");
  console.log("wrote", path.basename(out));
  n++;
}
console.log(`\nRendered ${n} policy file(s) to markdown.`);
