import { Violation } from './types.js';

// ANSI terminal color codes
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const BG_RED = '\x1b[41m\x1b[37m';

export function formatTerminalOutput(violations: Violation[]): string {
  if (violations.length === 0) {
    return `${GREEN}${BOLD}✔ No secret leaks or unhandled environment credentials detected in staged changes!${RESET}\n`;
  }

  let out = `\n${BG_RED}${BOLD}  SECURITY ALERT: ACCIDENTAL SECRET COMMIT BLOCKED  ${RESET}\n`;
  out += `${RED}${BOLD}Found ${violations.length} secret/credential violation(s) in staged files:${RESET}\n\n`;

  const groupedByFile = new Map<string, Violation[]>();
  for (const v of violations) {
    const list = groupedByFile.get(v.filePath) || [];
    list.push(v);
    groupedByFile.set(v.filePath, list);
  }

  for (const [filePath, fileViolations] of groupedByFile.entries()) {
    out += `${CYAN}${BOLD}📁 ${filePath}${RESET}\n`;

    for (const v of fileViolations) {
      const sevColor = v.severity === 'CRITICAL' ? RED : YELLOW;
      out += `  ${sevColor}● [Line ${v.lineNumber}] ${BOLD}${v.patternName}${RESET} ${DIM}(${v.category})${RESET}\n`;
      out += `    ${DIM}Description:${RESET} ${v.description}\n`;
      out += `    ${DIM}Detected:${RESET}    ${RED}${BOLD}${v.maskedSecret}${RESET}`;
      if (v.entropy) {
        out += ` ${DIM}(Entropy: ${v.entropy})${RESET}`;
      }
      out += `\n`;
      out += `    ${DIM}Code:${RESET}        ${highlightLine(v.lineContent, v.matchedSecret)}\n\n`;
    }
  }

  out += `${BOLD}How to resolve before committing:${RESET}\n`;
  out += `  1. Remove secret from code or replace with process.env.YOUR_KEY\n`;
  out += `  2. Unstage file: ${CYAN}git restore --staged <file>${RESET}\n`;
  out += `  3. Store real keys in ${CYAN}.env${RESET} (added to .gitignore)\n`;
  out += `  4. If this is a false positive, append ${DIM}// env-scanner-ignore${RESET} to the line.\n`;

  return out;
}

function highlightLine(line: string, secret: string): string {
  if (!secret) return line;
  const idx = line.indexOf(secret);
  if (idx === -1) return line;

  const before = line.substring(0, idx);
  const matched = line.substring(idx, idx + secret.length);
  const after = line.substring(idx + secret.length);

  return `${DIM}${before}${RESET}${RED}${BOLD}${matched}${RESET}${DIM}${after}${RESET}`;
}
