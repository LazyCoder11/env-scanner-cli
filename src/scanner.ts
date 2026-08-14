import fs from 'fs';
import path from 'path';
import { BUILTIN_PATTERNS } from './patterns.js';
import { calculateShannonEntropy, maskSecret } from './entropy.js';
import { getStagedDiff } from './git.js';
import { loadConfig, isFileIgnored } from './config.js';
import { Violation, ScannerOptions, StagedFile } from './types.js';

export function runScan(options: ScannerOptions = {}): Violation[] {
  const config = loadConfig();
  const minEntropy = options.minEntropy ?? config.entropyThreshold ?? 4.2;
  const violations: Violation[] = [];

  let filesToScan: { filePath: string; lines: { lineNumber: number; content: string }[] }[] = [];

  if (options.scanAll) {
    // Scan all tracked text files in workspace
    filesToScan = getAllFilesToScan(config);
  } else {
    // Default: scan git staged changes
    const stagedFiles = getStagedDiff();
    for (const file of stagedFiles) {
      if (isFileIgnored(file.filePath, config)) continue;
      const lines: { lineNumber: number; content: string }[] = [];
      for (const hunk of file.hunks) {
        lines.push(...hunk.addedLines);
      }
      filesToScan.push({ filePath: file.filePath, lines });
    }
  }

  for (const file of filesToScan) {
    if (isFileIgnored(file.filePath, config)) continue;

    for (const { lineNumber, content } of file.lines) {
      // Check for inline suppression comment
      if (content.includes('env-scanner-ignore') || content.includes('secret-ignore')) {
        continue;
      }

      for (const pattern of BUILTIN_PATTERNS) {
        pattern.regex.lastIndex = 0; // Reset state for global regex
        let match: RegExpExecArray | null;

        while ((match = pattern.regex.exec(content)) !== null) {
          const secretMatch = match[1] || match[0];
          const entropy = calculateShannonEntropy(secretMatch);

          // If pattern mandates entropy threshold, check it
          if (pattern.entropyThreshold && entropy < pattern.entropyThreshold) {
            continue;
          }

          violations.push({
            filePath: file.filePath,
            lineNumber,
            lineContent: content.trim(),
            matchedSecret: secretMatch,
            maskedSecret: maskSecret(secretMatch),
            patternId: pattern.id,
            patternName: pattern.name,
            category: pattern.category,
            severity: pattern.severity,
            description: pattern.description,
            entropy
          });
        }
      }
    }
  }

  return violations;
}

function getAllFilesToScan(config: ReturnType<typeof loadConfig>): { filePath: string; lines: { lineNumber: number; content: string }[] }[] {
  const result: { filePath: string; lines: { lineNumber: number; content: string }[] }[] = [];

  function walk(dir: string) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(process.cwd(), fullPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'graphify-out'].includes(entry.name)) continue;
        if (isFileIgnored(relativePath, config)) continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        if (isFileIgnored(relativePath, config)) continue;
        try {
          const fileContent = fs.readFileSync(fullPath, 'utf-8');
          const lines = fileContent.split('\n').map((content, idx) => ({
            lineNumber: idx + 1,
            content
          }));
          result.push({ filePath: relativePath, lines });
        } catch {
          // Skip binary files or unreadable files
        }
      }
    }
  }

  walk(process.cwd());
  return result;
}
