export interface SecretPattern {
  id: string;
  name: string;
  category: 'cloud' | 'ai' | 'payment' | 'vcs' | 'auth' | 'generic' | 'private_key' | 'messaging' | 'devops' | 'database' | 'social' | 'paas';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  regex: RegExp;
  entropyThreshold?: number;
  description: string;
}

export interface DiffHunk {
  content: string;
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  addedLines: { lineNumber: number; content: string }[];
}

export interface StagedFile {
  filePath: string;
  status: 'added' | 'modified' | 'renamed';
  hunks: DiffHunk[];
}

export interface Violation {
  filePath: string;
  lineNumber: number;
  lineContent: string;
  matchedSecret: string;
  maskedSecret: string;
  patternId: string;
  patternName: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  entropy?: number;
}

export interface ScannerOptions {
  stagedOnly?: boolean;
  scanAll?: boolean;
  minEntropy?: number;
  ignorePatterns?: string[];
  jsonOutput?: boolean;
  quiet?: boolean;
}

export interface Config {
  ignoreFiles?: string[];
  ignoreRules?: string[];
  entropyThreshold?: number;
}
