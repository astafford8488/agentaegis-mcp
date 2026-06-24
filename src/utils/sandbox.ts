import { execFile } from "child_process";
import { promisify } from "util";
import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";
import { v4 as uuidv4 } from "uuid";
import { validateGitUrl } from "./sanitize.js";

const execFileAsync = promisify(execFile);

const DEFAULT_TIMEOUT_MS = 300_000; // 5 minutes
const MAX_REPO_SIZE_MB = 500;

export interface SandboxedExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export async function execInSandbox(
  command: string,
  args: string[],
  options: {
    timeout?: number;
    cwd?: string;
    env?: Record<string, string>;
    maxBuffer?: number;
  } = {}
): Promise<SandboxedExecResult> {
  const timeout = options.timeout || DEFAULT_TIMEOUT_MS;
  const maxBuffer = options.maxBuffer || 50 * 1024 * 1024; // 50MB

  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout,
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      maxBuffer,
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (err: unknown) {
    const error = err as { stdout?: string; stderr?: string; code?: number | string };
    if (error.code === "ETIMEDOUT" || error.code === "ERR_CHILD_PROCESS_TIMEOUT") {
      return { stdout: "", stderr: "Scan timed out", exitCode: 124 };
    }
    return {
      stdout: error.stdout || "",
      stderr: error.stderr || String(err),
      exitCode: typeof error.code === "number" ? error.code : 1,
    };
  }
}

export async function createTempDir(): Promise<string> {
  const dir = path.join(os.tmpdir(), `aegis-${uuidv4()}`);
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

export async function cleanupTempDir(dir: string): Promise<void> {
  try {
    await fs.rm(dir, { recursive: true, force: true });
  } catch {
    // Best effort cleanup
  }
}

export async function cloneRepo(
  url: string,
  targetDir: string
): Promise<{ success: boolean; error?: string }> {
  // SSRF guard: every clone-based tool routes through here, so validating the
  // URL once protects all of them (sast/secret/dependency/mcp-plugin/skill scans).
  const urlCheck = await validateGitUrl(url);
  if (!urlCheck.valid) {
    return { success: false, error: `Blocked git URL: ${urlCheck.reason}` };
  }

  const result = await execInSandbox("git", ["clone", "--depth=1", "--single-branch", url, targetDir], {
    timeout: 120_000,
  });

  if (result.exitCode !== 0) {
    return { success: false, error: result.stderr };
  }

  const dirSize = await getDirectorySize(targetDir);
  if (dirSize > MAX_REPO_SIZE_MB * 1024 * 1024) {
    await cleanupTempDir(targetDir);
    return { success: false, error: `Repository exceeds ${MAX_REPO_SIZE_MB}MB limit` };
  }

  return { success: true };
}

async function getDirectorySize(dir: string): Promise<number> {
  let size = 0;
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      size += await getDirectorySize(fullPath);
    } else {
      const stat = await fs.stat(fullPath);
      size += stat.size;
    }
  }
  return size;
}
