import { execInSandbox } from "../utils/sandbox.js";
import { sanitizeShellArg } from "../utils/sanitize.js";
import type { Finding } from "../types/security.js";

export type NmapScanType = "quick" | "standard" | "deep";

interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

export interface NmapResult {
  target: string;
  ports: NmapPort[];
  os_detection?: string;
  scan_time_seconds: number;
  raw_output: string;
}

function getScanArgs(scanType: NmapScanType, target: string, portRange?: string): string[] {
  const sanitizedTarget = sanitizeShellArg(target);
  const args: string[] = ["-oX", "-"]; // XML output to stdout

  switch (scanType) {
    case "quick":
      args.push("-sV", "-T4", "--top-ports", "100");
      break;
    case "standard":
      args.push("-sV", "-sC", "--top-ports", "1000");
      break;
    case "deep":
      args.push("-sV", "-sC", "-T3");
      if (portRange) {
        args.push("-p", sanitizeShellArg(portRange));
      } else {
        args.push("-p-");
      }
      break;
  }

  if (portRange && scanType !== "deep") {
    args.push("-p", sanitizeShellArg(portRange));
  }

  args.push(sanitizedTarget);
  return args;
}

function parseNmapXML(xml: string): NmapPort[] {
  const ports: NmapPort[] = [];
  const portRegex = /<port protocol="([^"]+)" portid="(\d+)">\s*<state state="([^"]+)"[^\/]*\/>\s*<service name="([^"]*)"[^>]*product="([^"]*)"[^>]*version="([^"]*)"[^\/]*\/>/g;

  let match;
  while ((match = portRegex.exec(xml)) !== null) {
    ports.push({
      protocol: match[1],
      port: parseInt(match[2]),
      state: match[3],
      service: match[4],
      version: `${match[5]} ${match[6]}`.trim(),
    });
  }

  // Fallback simpler regex for ports without full service info
  if (ports.length === 0) {
    const simpleRegex = /<port protocol="([^"]+)" portid="(\d+)">\s*<state state="([^"]+)"[^\/]*\/>\s*<service name="([^"]*)"[^\/]*\/>/g;
    while ((match = simpleRegex.exec(xml)) !== null) {
      ports.push({
        protocol: match[1],
        port: parseInt(match[2]),
        state: match[3],
        service: match[4],
        version: "",
      });
    }
  }

  return ports;
}

export async function runNmapScan(
  target: string,
  scanType: NmapScanType,
  portRange?: string
): Promise<NmapResult> {
  const args = getScanArgs(scanType, target, portRange);
  const timeoutMs = scanType === "deep" ? 600_000 : 300_000;

  const startTime = Date.now();
  const result = await execInSandbox(
    process.env.NMAP_PATH || "nmap",
    args,
    { timeout: timeoutMs }
  );

  const scanTime = (Date.now() - startTime) / 1000;
  const ports = parseNmapXML(result.stdout);

  return {
    target,
    ports,
    scan_time_seconds: scanTime,
    raw_output: result.stdout,
  };
}

export function nmapResultToFindings(result: NmapResult): Finding[] {
  const findings: Finding[] = [];

  for (const port of result.ports) {
    if (port.state !== "open") continue;

    // Flag commonly dangerous open ports
    const dangerousPorts: Record<number, string> = {
      21: "FTP - often allows anonymous access or transmits credentials in cleartext",
      23: "Telnet - transmits all data including credentials in cleartext",
      445: "SMB - commonly exploited for lateral movement",
      3389: "RDP - frequently targeted for brute force attacks",
      5900: "VNC - often misconfigured without authentication",
      6379: "Redis - frequently exposed without authentication",
      27017: "MongoDB - often exposed without authentication",
      9200: "Elasticsearch - commonly exposed without authentication",
    };

    if (dangerousPorts[port.port]) {
      findings.push({
        id: `nmap-${port.port}-${port.protocol}`,
        title: `Potentially dangerous port open: ${port.port}/${port.protocol} (${port.service})`,
        description: dangerousPorts[port.port],
        severity: "high",
        affected_system: result.target,
        affected_component: `${port.port}/${port.protocol}`,
        remediation: `Review if port ${port.port} needs to be publicly accessible. If not required, block at the firewall level.`,
      });
    }
  }

  return findings;
}
