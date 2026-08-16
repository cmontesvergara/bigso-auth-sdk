import { readFile, readdir, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const PATTERNS = [
  { name: "JWT", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: "Authorization bearer", pattern: /authorization["']?\s*[:=]\s*["']?bearer\s+[^\s,"'}]+/gi },
  { name: "access token field", pattern: /["']accessToken["']\s*:\s*["'][^"']+["']/g },
  { name: "refresh token field", pattern: /["']refreshToken["']\s*:\s*["'][^"']+["']/g },
  { name: "token hash field", pattern: /["'](?:tokenHash|computedHash|refreshHash)["']\s*:\s*["'][^"']+["']/gi },
];

async function filesAt(path) {
  const info = await stat(path);
  if (info.isFile()) return [path];
  const entries = await readdir(path, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => filesAt(resolve(path, entry.name))));
  return nested.flat();
}

export function findAuthLeaks(text) {
  return PATTERNS.flatMap(({ name, pattern }) => {
    pattern.lastIndex = 0;
    return [...text.matchAll(pattern)].map((match) => ({ name, index: match.index ?? 0 }));
  });
}

export async function scanAuthArtifacts(paths) {
  const files = (await Promise.all(paths.map((path) => filesAt(resolve(path))))).flat();
  const findings = [];
  for (const file of files) {
    const text = await readFile(file, "utf8");
    for (const finding of findAuthLeaks(text)) findings.push({ file, ...finding });
  }
  return findings;
}

const invokedDirectly = process.argv[1]
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (invokedDirectly) {
  const paths = process.argv.slice(2);
  if (paths.length === 0) {
    console.error("Usage: scan-auth-artifacts <file-or-directory> [...]");
    process.exitCode = 2;
  } else {
    const findings = await scanAuthArtifacts(paths);
    if (findings.length > 0) {
      for (const { file, name } of findings) console.error(`${file}: forbidden ${name} material`);
      process.exitCode = 1;
    } else {
      console.log(`Auth artifact scan passed (${paths.length} target${paths.length === 1 ? "" : "s"})`);
    }
  }
}
