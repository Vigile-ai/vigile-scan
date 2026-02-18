// ============================================================
// Vigile CLI — Skill File Discovery
// ============================================================
// Discovers agent skill files (SKILL.md, .mdc rules, CLAUDE.md,
// SOUL.md, MEMORY.md) across all supported AI tools.
//
// Scan locations:
//   Claude Code:     .claude/skills/*/SKILL.md (project)
//                    ~/.claude/skills/*/SKILL.md (global)
//   GitHub Copilot:  .github/skills/*/SKILL.md (project)
//   Cursor:          .cursor/rules/*.mdc (project)
//                    ~/.cursor/rules/*.mdc (global)
//   Memory Files:    CLAUDE.md, SOUL.md, MEMORY.md (project root)
//                    ~/.claude/CLAUDE.md (global)

import { readFile, stat } from 'fs/promises';
import { existsSync } from 'fs';
import { join, basename, dirname } from 'path';
import { glob } from 'glob';
import { getHome } from './utils.js';
import type {
  SkillEntry,
  SkillSource,
  SkillFileType,
  SkillDiscoveryResult,
} from '../types/index.js';

/**
 * Discover all agent skill files on this machine.
 */
export async function discoverAllSkills(): Promise<SkillDiscoveryResult> {
  const skills: SkillEntry[] = [];
  const errors: Array<{ source: SkillSource; error: string }> = [];
  let locationsChecked = 0;
  let locationsFound = 0;

  const discoverers: Array<{
    source: SkillSource;
    fn: () => Promise<SkillEntry[]>;
  }> = [
    { source: 'claude-code', fn: discoverClaudeCodeSkills },
    { source: 'github-copilot', fn: discoverGitHubCopilotSkills },
    { source: 'cursor', fn: discoverCursorRules },
    { source: 'memory-file', fn: discoverMemoryFiles },
  ];

  for (const { source, fn } of discoverers) {
    locationsChecked++;
    try {
      const found = await fn();
      if (found.length > 0) {
        locationsFound++;
        skills.push(...found);
      }
    } catch (err) {
      errors.push({
        source,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return { skills, locationsChecked, locationsFound, errors };
}

/**
 * Discover Claude Code skill files.
 * Project: .claude/skills/* /SKILL.md
 * Global:  ~/.claude/skills/* /SKILL.md
 */
async function discoverClaudeCodeSkills(): Promise<SkillEntry[]> {
  const home = getHome();
  const skills: SkillEntry[] = [];

  // Project-local skills
  const projectPatterns = [
    join(process.cwd(), '.claude', 'skills', '*', 'SKILL.md'),
    join(process.cwd(), '.claude', 'commands', '**', '*.md'),
  ];

  for (const pattern of projectPatterns) {
    const files = await glob(pattern, { absolute: true });
    for (const filePath of files) {
      const entry = await readSkillFile(filePath, 'claude-code', 'skill.md', 'project');
      if (entry) skills.push(entry);
    }
  }

  // Global skills
  const globalPatterns = [
    join(home, '.claude', 'skills', '*', 'SKILL.md'),
    join(home, '.claude', 'commands', '**', '*.md'),
  ];

  for (const pattern of globalPatterns) {
    const files = await glob(pattern, { absolute: true });
    for (const filePath of files) {
      const entry = await readSkillFile(filePath, 'claude-code', 'skill.md', 'global');
      if (entry) skills.push(entry);
    }
  }

  return skills;
}

/**
 * Discover GitHub Copilot skill files.
 * Project: .github/skills/* /SKILL.md
 */
async function discoverGitHubCopilotSkills(): Promise<SkillEntry[]> {
  const skills: SkillEntry[] = [];

  const patterns = [
    join(process.cwd(), '.github', 'skills', '*', 'SKILL.md'),
    join(process.cwd(), '.github', 'copilot', '**', '*.md'),
  ];

  for (const pattern of patterns) {
    const files = await glob(pattern, { absolute: true });
    for (const filePath of files) {
      const entry = await readSkillFile(filePath, 'github-copilot', 'skill.md', 'project');
      if (entry) skills.push(entry);
    }
  }

  return skills;
}

/**
 * Discover Cursor .mdc rule files.
 * Project: .cursor/rules/*.mdc
 * Global:  ~/.cursor/rules/*.mdc
 */
async function discoverCursorRules(): Promise<SkillEntry[]> {
  const home = getHome();
  const skills: SkillEntry[] = [];

  // Project-local rules
  const projectPattern = join(process.cwd(), '.cursor', 'rules', '*.mdc');
  const projectFiles = await glob(projectPattern, { absolute: true });
  for (const filePath of projectFiles) {
    const entry = await readSkillFile(filePath, 'cursor', 'mdc-rule', 'project');
    if (entry) skills.push(entry);
  }

  // Also check .cursorrules (legacy single file)
  const legacyPath = join(process.cwd(), '.cursorrules');
  if (existsSync(legacyPath)) {
    const entry = await readSkillFile(legacyPath, 'cursor', 'mdc-rule', 'project');
    if (entry) skills.push(entry);
  }

  // Global rules
  const globalPattern = join(home, '.cursor', 'rules', '*.mdc');
  const globalFiles = await glob(globalPattern, { absolute: true });
  for (const filePath of globalFiles) {
    const entry = await readSkillFile(filePath, 'cursor', 'mdc-rule', 'global');
    if (entry) skills.push(entry);
  }

  return skills;
}

/**
 * Discover memory/instruction files at project root and global locations.
 * CLAUDE.md, SOUL.md, MEMORY.md
 */
async function discoverMemoryFiles(): Promise<SkillEntry[]> {
  const home = getHome();
  const skills: SkillEntry[] = [];
  const cwd = process.cwd();

  const memoryFiles: Array<{
    path: string;
    fileType: SkillFileType;
    scope: 'project' | 'global';
  }> = [
    // Project-level memory files
    { path: join(cwd, 'CLAUDE.md'), fileType: 'claude.md', scope: 'project' },
    { path: join(cwd, '.claude', 'CLAUDE.md'), fileType: 'claude.md', scope: 'project' },
    { path: join(cwd, 'SOUL.md'), fileType: 'soul.md', scope: 'project' },
    { path: join(cwd, 'MEMORY.md'), fileType: 'memory.md', scope: 'project' },
    // Global memory files
    { path: join(home, '.claude', 'CLAUDE.md'), fileType: 'claude.md', scope: 'global' },
    { path: join(home, 'CLAUDE.md'), fileType: 'claude.md', scope: 'global' },
  ];

  for (const { path, fileType, scope } of memoryFiles) {
    if (existsSync(path)) {
      const entry = await readSkillFile(path, 'memory-file', fileType, scope);
      if (entry) skills.push(entry);
    }
  }

  return skills;
}

/**
 * Read a skill file and return a SkillEntry.
 */
async function readSkillFile(
  filePath: string,
  source: SkillSource,
  fileType: SkillFileType,
  scope: 'project' | 'global'
): Promise<SkillEntry | null> {
  try {
    const content = await readFile(filePath, 'utf-8');
    const fileStat = await stat(filePath);

    // Derive skill name from context
    const name = deriveSkillName(filePath, fileType);

    return {
      name,
      source,
      fileType,
      filePath,
      content,
      size: fileStat.size,
      scope,
    };
  } catch {
    return null;
  }
}

/**
 * Derive a human-readable skill name from a file path.
 */
function deriveSkillName(filePath: string, fileType: SkillFileType): string {
  switch (fileType) {
    case 'skill.md': {
      // .claude/skills/my-skill/SKILL.md → "my-skill"
      const parentDir = basename(dirname(filePath));
      return parentDir === 'skills' ? basename(filePath, '.md') : parentDir;
    }
    case 'mdc-rule': {
      // .cursor/rules/my-rule.mdc → "my-rule"
      const name = basename(filePath);
      return name.replace(/\.(mdc|cursorrules?)$/, '') || name;
    }
    case 'claude.md':
      return 'CLAUDE.md';
    case 'soul.md':
      return 'SOUL.md';
    case 'memory.md':
      return 'MEMORY.md';
    default:
      return basename(filePath);
  }
}
