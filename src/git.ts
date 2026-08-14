import { execSync } from 'child_process';
import { StagedFile, DiffHunk } from './types.js';

export function getStagedDiff(): StagedFile[] {
  try {
    // Get list of staged file paths
    const statusOutput = execSync('git diff --staged --name-status', { encoding: 'utf-8' });
    if (!statusOutput.trim()) {
      return [];
    }

    const files: StagedFile[] = [];
    const lines = statusOutput.trim().split('\n');

    for (const line of lines) {
      const parts = line.split('\t');
      if (parts.length < 2) continue;

      const statusCode = parts[0].trim();
      const filePath = parts[parts.length - 1].trim();

      // Skip deleted files
      if (statusCode.startsWith('D')) continue;

      const status: StagedFile['status'] = statusCode.startsWith('A')
        ? 'added'
        : statusCode.startsWith('R')
        ? 'renamed'
        : 'modified';

      const hunks = getFileDiffHunks(filePath);
      if (hunks.length > 0) {
        files.push({ filePath, status, hunks });
      }
    }

    return files;
  } catch (err: any) {
    if (err.message && err.message.includes('not a git repository')) {
      throw new Error('Not inside a Git repository. Run this command inside a git workspace.');
    }
    return [];
  }
}

function getFileDiffHunks(filePath: string): DiffHunk[] {
  try {
    const rawDiff = execSync(`git diff --staged -U0 -- "${filePath}"`, { encoding: 'utf-8' });
    return parseUnifiedDiff(rawDiff);
  } catch {
    return [];
  }
}

export function parseUnifiedDiff(rawDiff: string): DiffHunk[] {
  const hunks: DiffHunk[] = [];
  const lines = rawDiff.split('\n');

  let currentHunk: DiffHunk | null = null;
  let currentLineNumber = 1;

  for (const line of lines) {
    if (line.startsWith('@@')) {
      // Hunk header: @@ -oldStart,oldLines +newStart,newLines @@
      const match = line.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
      if (match) {
        currentLineNumber = parseInt(match[1], 10);
        currentHunk = {
          content: line,
          oldStart: 0,
          oldLines: 0,
          newStart: currentLineNumber,
          newLines: match[2] ? parseInt(match[2], 10) : 1,
          addedLines: []
        };
        hunks.push(currentHunk);
      }
    } else if (currentHunk) {
      if (line.startsWith('+') && !line.startsWith('+++')) {
        currentHunk.addedLines.push({
          lineNumber: currentLineNumber,
          content: line.substring(1)
        });
        currentLineNumber++;
      } else if (!line.startsWith('-')) {
        currentLineNumber++;
      }
    }
  }

  return hunks;
}
