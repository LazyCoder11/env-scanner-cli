import fs from 'fs';
import path from 'path';
import { Config } from './types.js';

const CONFIG_FILENAME = '.envscanner.json';
const IGNORE_FILENAME = '.envignore';

export function loadConfig(cwd: string = process.cwd()): Config {
  const config: Config = {
    ignoreFiles: ['.env.example', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'graphify-out/'],
    ignoreRules: [],
    entropyThreshold: 4.2
  };

  const configPath = path.join(cwd, CONFIG_FILENAME);
  if (fs.existsSync(configPath)) {
    try {
      const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      if (userConfig.ignoreFiles) config.ignoreFiles?.push(...userConfig.ignoreFiles);
      if (userConfig.ignoreRules) config.ignoreRules?.push(...userConfig.ignoreRules);
      if (userConfig.entropyThreshold) config.entropyThreshold = userConfig.entropyThreshold;
    } catch {
      // Ignore invalid config formatting
    }
  }

  const ignorePath = path.join(cwd, IGNORE_FILENAME);
  if (fs.existsSync(ignorePath)) {
    try {
      const ignoreLines = fs.readFileSync(ignorePath, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
      config.ignoreFiles?.push(...ignoreLines);
    } catch {
      // Ignore reading errors
    }
  }

  return config;
}

export function isFileIgnored(filePath: string, config: Config): boolean {
  if (!config.ignoreFiles) return false;
  return config.ignoreFiles.some(pattern => {
    if (pattern.endsWith('/')) {
      return filePath.startsWith(pattern) || filePath.includes('/' + pattern);
    }
    return filePath === pattern || filePath.endsWith('/' + pattern);
  });
}
