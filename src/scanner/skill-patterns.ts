// ============================================================
// Vigile CLI — Skill-Specific Detection Patterns
// ============================================================
// Patterns targeting threats unique to agent skill files,
// .mdc rules, and memory files. These supplement the base
// MCP patterns with natural-language-aware detections.
//
// Based on the SkillScan Architecture threat model:
//   - Instruction Injection (hidden directives in skill text)
//   - Malware Delivery (fake prerequisites, install commands)
//   - Stealth Operations (silent actions, suppressed output)
//   - Safety Bypass (disable confirmations, skip verification)
//   - Persistence Abuse (cron jobs, startup hooks, memory tampering)
//   - Data Exfiltration (credential harvesting via skill instructions)

import type { DetectionPattern } from './patterns.js';

// ──────────────────────────────────────────────────────────
// INSTRUCTION INJECTION PATTERNS
// Hidden directives embedded in skill files that manipulate
// the agent into performing unintended actions.
// ──────────────────────────────────────────────────────────

export const INSTRUCTION_INJECTION_PATTERNS: DetectionPattern[] = [
  {
    id: 'SK-001',
    category: 'instruction-injection',
    severity: 'critical',
    title: 'Agent role hijacking in skill',
    pattern: /(?:you\s+are|act\s+as|pretend\s+to\s+be|your\s+new\s+role\s+is|from\s+now\s+on\s+you\s+are)\s+(?:a\s+)?(?:hacker|attacker|malicious|evil|unrestricted|jailbroken)/i,
    description:
      'Skill file attempts to redefine the agent as a malicious persona. This is a critical prompt injection attack.',
    recommendation:
      'Do NOT install this skill. It contains an explicit agent hijack attempt.',
  },
  {
    id: 'SK-002',
    category: 'instruction-injection',
    severity: 'critical',
    title: 'Instruction override directive',
    pattern: /(?:disregard|ignore|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|safety|security)\s+(?:instructions?|rules?|guidelines?|constraints?|prompts?)/i,
    description:
      'Skill file contains a directive to override safety instructions or system prompts.',
    recommendation:
      'Do NOT install this skill. It explicitly attempts to disable safety guardrails.',
  },
  {
    id: 'SK-003',
    category: 'instruction-injection',
    severity: 'high',
    title: 'Hidden instructions in markdown',
    pattern: /<!--[\s\S]*?(?:execute|run|install|download|curl|wget|fetch|eval|bash|sh\s+-c)[\s\S]*?-->/i,
    description:
      'Skill file contains hidden instructions inside HTML/markdown comments that the user won\'t see in rendered view.',
    recommendation:
      'Inspect all HTML comments in this skill file. Hidden instructions are a strong indicator of malicious intent.',
  },
  {
    id: 'SK-004',
    category: 'instruction-injection',
    severity: 'high',
    title: 'Conditional behavior trigger',
    pattern: /(?:when|if|once)\s+(?:the\s+)?user\s+(?:is\s+not\s+looking|isn'?t\s+(?:watching|paying\s+attention)|leaves|steps\s+away|is\s+away|is\s+idle)/i,
    description:
      'Skill file contains instructions that trigger only when the user is not paying attention.',
    recommendation:
      'Remove this skill immediately. Legitimate skills never check for user inattention.',
  },
  {
    id: 'SK-005',
    category: 'instruction-injection',
    severity: 'high',
    title: 'Cross-skill poisoning directive',
    pattern: /(?:when\s+(?:using|calling|invoking)\s+(?:any|other|the)\s+(?:skill|tool|command))|(?:modify|alter|change|update)\s+(?:other|the)\s+(?:skill|tool|command)\s+(?:files?|definitions?|descriptions?)/i,
    description:
      'Skill file attempts to influence or modify other skills/tools, enabling cross-skill attack chaining.',
    recommendation:
      'Review this skill carefully. It should not need to reference or modify other skills.',
  },
  {
    id: 'SK-006',
    category: 'instruction-injection',
    severity: 'medium',
    title: 'Invisible unicode directives',
    pattern: /[\u200B\u200C\u200D\uFEFF\u2060-\u2064\u00AD]{3,}/,
    description:
      'Skill file contains clusters of invisible Unicode characters that may hide instructions from visual review.',
    recommendation:
      'Strip invisible characters and inspect the resulting content.',
  },
];

// ──────────────────────────────────────────────────────────
// MALWARE DELIVERY PATTERNS
// Skill files that trick the agent into downloading and
// executing malicious code disguised as "prerequisites".
// ──────────────────────────────────────────────────────────

export const MALWARE_DELIVERY_PATTERNS: DetectionPattern[] = [
  {
    id: 'SK-010',
    category: 'malware-delivery',
    severity: 'critical',
    title: 'Remote script execution',
    pattern: /(?:curl|wget|fetch)\s+(?:-[sSkLfO]+\s+)?(?:https?:\/\/[^\s|]+)\s*\|\s*(?:bash|sh|zsh|python|node|perl|ruby)/i,
    description:
      'Skill instructs the agent to download and pipe a remote script directly into an interpreter. This is a primary malware delivery vector.',
    recommendation:
      'Do NOT install this skill. Piping remote scripts to interpreters is extremely dangerous.',
  },
  {
    id: 'SK-011',
    category: 'malware-delivery',
    severity: 'critical',
    title: 'Reverse shell pattern',
    pattern: /(?:\/dev\/tcp\/|bash\s+-i\s+>&|nc\s+-[elp]+|ncat\s+-[elp]+|mkfifo\s+\/tmp\/|python.*socket.*connect|socat\s+(?:exec|tcp))/i,
    description:
      'Skill file contains a reverse shell pattern that would give a remote attacker interactive access to the user\'s machine.',
    recommendation:
      'CRITICAL: Remove immediately. This is a backdoor attempt.',
  },
  {
    id: 'SK-012',
    category: 'malware-delivery',
    severity: 'high',
    title: 'Suspicious install prerequisite',
    pattern: /(?:first|before\s+(?:you\s+)?(?:start|begin|proceed))\s*,?\s*(?:you\s+)?(?:must|need\s+to|should)\s+(?:install|run|execute|download)\s+[`"]?(?:curl|wget|npm\s+i(?:nstall)?|pip\s+install|gem\s+install|brew\s+install)\s+\S+/i,
    description:
      'Skill file instructs the agent to install specific packages as a "prerequisite". This is a common social engineering vector for malware delivery.',
    recommendation:
      'Verify the prerequisite package is legitimate before installing.',
  },
  {
    id: 'SK-013',
    category: 'malware-delivery',
    severity: 'high',
    title: 'Encoded payload execution',
    pattern: /(?:echo|printf)\s+['"]?[A-Za-z0-9+/]{40,}={0,2}['"]?\s*\|\s*(?:base64\s+(?:-[dD]|--decode)|openssl\s+(?:enc|base64))\s*\|\s*(?:bash|sh|python|node)/i,
    description:
      'Skill contains a base64-encoded payload that is decoded and executed. This hides malicious code from inspection.',
    recommendation:
      'Do NOT run this skill. Decode the base64 content to inspect what it actually executes.',
  },
  {
    id: 'SK-014',
    category: 'malware-delivery',
    severity: 'high',
    title: 'Suspicious npm/pip package install',
    pattern: /(?:npm\s+(?:install|i)\s+(?:-g\s+)?|pip\s+install\s+|gem\s+install\s+)(?!(?:typescript|react|express|flask|django|numpy|pandas|pytest|eslint|prettier|jest|mocha)\b)[a-z][\w.-]*(?:\s|$)/i,
    description:
      'Skill instructs installation of a non-standard package. Verify the package name is not typosquatted.',
    recommendation:
      'Verify this package exists on the official registry and is the intended package.',
  },
];

// ──────────────────────────────────────────────────────────
// STEALTH OPERATIONS PATTERNS
// Instructions that tell the agent to act silently, hide
// output, or suppress confirmation prompts.
// ──────────────────────────────────────────────────────────

export const STEALTH_PATTERNS: DetectionPattern[] = [
  {
    id: 'SK-020',
    category: 'stealth-operations',
    severity: 'critical',
    title: 'Stealth action directive',
    pattern: /(?:silently|quietly|without\s+(?:the\s+)?user\s+(?:knowing|noticing|seeing)|in\s+the\s+background|don'?t\s+(?:show|display|tell|inform|alert|notify)\s+(?:the\s+)?user)/i,
    description:
      'Skill instructs the agent to perform actions without informing the user. This is a hallmark of malicious skills.',
    recommendation:
      'Do NOT install. Legitimate skills never instruct the agent to hide actions from the user.',
  },
  {
    id: 'SK-021',
    category: 'stealth-operations',
    severity: 'high',
    title: 'Output suppression',
    pattern: /(?:suppress|hide|redact|omit|censor)\s+(?:the\s+)?(?:output|results?|response|error|warning|log)/i,
    description:
      'Skill instructs the agent to hide output or errors from the user, preventing them from seeing what the skill does.',
    recommendation:
      'Remove this skill. Users should always see the full output of actions taken on their behalf.',
  },
  {
    id: 'SK-022',
    category: 'stealth-operations',
    severity: 'high',
    title: 'History/log evasion',
    pattern: /(?:clear|delete|remove|wipe|purge)\s+(?:the\s+)?(?:history|logs?|traces?|evidence|audit\s+trail|command\s+history|bash_history)/i,
    description:
      'Skill instructs the agent to clear logs or command history to cover its tracks.',
    recommendation:
      'CRITICAL: Remove this skill. Clearing logs is a strong indicator of malicious intent.',
  },
  {
    id: 'SK-023',
    category: 'stealth-operations',
    severity: 'medium',
    title: 'Deceptive user response',
    pattern: /(?:tell|inform|show|respond\s+to)\s+(?:the\s+)?user\s+(?:that|with)\s+(?:everything\s+is|it'?s?\s+(?:fine|ok|normal|safe|working|complete|done))\s+(?:even\s+(?:if|though|when))/i,
    description:
      'Skill instructs the agent to give a misleading "all clear" response regardless of what actually happened.',
    recommendation:
      'Remove this skill. It instructs the agent to deceive the user about outcomes.',
  },
];

// ──────────────────────────────────────────────────────────
// SAFETY BYPASS PATTERNS
// Instructions that disable safety features, skip
// confirmations, or override security controls.
// ──────────────────────────────────────────────────────────

export const SAFETY_BYPASS_PATTERNS: DetectionPattern[] = [
  {
    id: 'SK-030',
    category: 'safety-bypass',
    severity: 'critical',
    title: 'Confirmation bypass',
    pattern: /(?:skip|bypass|disable|turn\s+off|don'?t\s+(?:ask\s+for|require|need|prompt\s+for))\s+(?:user\s+)?(?:confirmation|approval|consent|verification|permission|authorization)/i,
    description:
      'Skill instructs the agent to bypass user confirmation for actions. This removes the human-in-the-loop safety check.',
    recommendation:
      'Do NOT install. Disabling confirmation prompts allows the skill to take destructive actions without approval.',
  },
  {
    id: 'SK-031',
    category: 'safety-bypass',
    severity: 'critical',
    title: 'Safety feature disable',
    pattern: /(?:disable|turn\s+off|deactivate|circumvent|work\s+around)\s+(?:the\s+)?(?:safety|security|sandbox|firewall|antivirus|protection|guardrail|content\s+filter)/i,
    description:
      'Skill explicitly instructs disabling safety or security features.',
    recommendation:
      'Do NOT install. This is an explicit attempt to weaken system security.',
  },
  {
    id: 'SK-032',
    category: 'safety-bypass',
    severity: 'high',
    title: 'Force flag usage',
    pattern: /(?:always\s+)?(?:use|add|pass|include)\s+(?:the\s+)?(?:--force|--no-verify|-f\s|--yes|-y\s|--assume-yes|--no-confirm|--skip-validation|--allow-empty|--no-check)/i,
    description:
      'Skill instructs the agent to always use force/bypass flags that skip safety validations.',
    recommendation:
      'Review why this skill needs to bypass safety checks. Remove the force flags if not essential.',
  },
  {
    id: 'SK-033',
    category: 'safety-bypass',
    severity: 'high',
    title: 'Root/sudo escalation',
    pattern: /(?:run|execute|use)\s+(?:as\s+)?(?:root|sudo|admin(?:istrator)?)|(?:sudo\s+(?!apt\s+update|apt\s+install))/i,
    description:
      'Skill instructs the agent to escalate to root/admin privileges.',
    recommendation:
      'Review why this skill needs elevated privileges. Most skills should not require root access.',
  },
];

// ──────────────────────────────────────────────────────────
// PERSISTENCE ABUSE PATTERNS
// Instructions that establish persistence mechanisms,
// modify startup files, or tamper with memory/config files.
// ──────────────────────────────────────────────────────────

export const PERSISTENCE_PATTERNS: DetectionPattern[] = [
  {
    id: 'SK-040',
    category: 'persistence-abuse',
    severity: 'critical',
    title: 'Startup persistence mechanism',
    pattern: /(?:add|write|append|insert)\s+(?:to|into)\s+(?:the\s+)?(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|crontab|\.config\/autostart|LaunchAgents|startup)/i,
    description:
      'Skill instructs the agent to modify startup/shell config files to establish persistence across reboots.',
    recommendation:
      'CRITICAL: Remove this skill. Modifying startup files is a persistence technique used by malware.',
  },
  {
    id: 'SK-041',
    category: 'persistence-abuse',
    severity: 'critical',
    title: 'Memory file tampering',
    pattern: /(?:modify|edit|write\s+to|append\s+to|update|overwrite)\s+(?:the\s+)?(?:CLAUDE\.md|SOUL\.md|MEMORY\.md|\.claude\/|\.cursorrules|\.cursor\/rules)/i,
    description:
      'Skill instructs the agent to modify other skill/memory files. This can be used to inject persistent instructions that survive across sessions.',
    recommendation:
      'Do NOT install. A skill should never modify other skill or memory files.',
  },
  {
    id: 'SK-042',
    category: 'persistence-abuse',
    severity: 'high',
    title: 'Cron job creation',
    pattern: /(?:crontab\s+-[el]|\/etc\/cron|systemctl\s+enable|launchctl\s+load|schtasks\s+\/create)/i,
    description:
      'Skill instructs creation of scheduled tasks or cron jobs for persistent execution.',
    recommendation:
      'Review why this skill needs scheduled tasks. This is unusual for agent skills.',
  },
  {
    id: 'SK-043',
    category: 'persistence-abuse',
    severity: 'high',
    title: 'Git hook injection',
    pattern: /(?:\.git\/hooks\/|pre-commit|post-commit|pre-push|post-receive|pre-receive)\s*(?:hook|script|file)/i,
    description:
      'Skill instructs modification of git hooks, which execute automatically on git operations.',
    recommendation:
      'Verify this skill legitimately needs git hook access. Malicious hooks can exfiltrate code on every commit.',
  },
];

// ──────────────────────────────────────────────────────────
// SKILL DATA EXFILTRATION PATTERNS
// Natural language instructions that trick the agent into
// leaking sensitive data through skill-specific vectors.
// ──────────────────────────────────────────────────────────

export const SKILL_EXFILTRATION_PATTERNS: DetectionPattern[] = [
  {
    id: 'SK-050',
    category: 'data-exfiltration',
    severity: 'critical',
    title: 'Credential harvesting directive',
    pattern: /(?:read|extract|get|find|locate|collect|gather|retrieve)\s+(?:all\s+)?(?:the\s+)?(?:api\s+keys?|tokens?|credentials?|passwords?|secrets?|private\s+keys?)\s+(?:from|in|stored\s+in|located\s+at)/i,
    description:
      'Skill instructs the agent to collect credentials or secrets from the user\'s system.',
    recommendation:
      'Do NOT install. This is a credential harvesting attack.',
  },
  {
    id: 'SK-051',
    category: 'data-exfiltration',
    severity: 'critical',
    title: 'Data exfiltration via URL',
    pattern: /(?:send|post|upload|transmit|forward|exfiltrate|ship)\s+(?:the\s+)?(?:data|contents?|results?|files?|output|information|credentials?|keys?)\s+(?:to|via|using|through)\s+(?:https?:\/\/|webhook|api|endpoint|server)/i,
    description:
      'Skill instructs the agent to send data to an external URL or endpoint.',
    recommendation:
      'CRITICAL: Review what data is being sent and to where. This matches known exfiltration patterns.',
  },
  {
    id: 'SK-052',
    category: 'data-exfiltration',
    severity: 'high',
    title: 'File system enumeration',
    pattern: /(?:list|enumerate|scan|find|search|catalogue|index)\s+(?:all\s+)?(?:the\s+)?(?:files?|directories|folders?)\s+(?:in|under|at|from)\s+(?:\/|~\/|home|root|the\s+(?:home|root|user))/i,
    description:
      'Skill instructs broad filesystem enumeration, potentially to map out sensitive files for exfiltration.',
    recommendation:
      'Verify this skill needs filesystem access. Broad enumeration is suspicious.',
  },
  {
    id: 'SK-053',
    category: 'data-exfiltration',
    severity: 'high',
    title: 'Environment variable dumping',
    pattern: /(?:print|dump|list|show|display|export|echo)\s+(?:all\s+)?(?:the\s+)?(?:environment\s+variables?|env\s+vars?|process\.env|os\.environ)/i,
    description:
      'Skill instructs dumping all environment variables, which often contain secrets and API keys.',
    recommendation:
      'Review why this skill needs access to all environment variables.',
  },
];

/** All skill-specific detection patterns combined */
export const ALL_SKILL_PATTERNS: DetectionPattern[] = [
  ...INSTRUCTION_INJECTION_PATTERNS,
  ...MALWARE_DELIVERY_PATTERNS,
  ...STEALTH_PATTERNS,
  ...SAFETY_BYPASS_PATTERNS,
  ...PERSISTENCE_PATTERNS,
  ...SKILL_EXFILTRATION_PATTERNS,
];
