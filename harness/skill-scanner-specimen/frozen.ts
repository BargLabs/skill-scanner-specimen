/**
 * The frozen configuration of the Cisco skill-scanner specimen.
 *
 * Everything the run and the score depend on is in this one object, and its canonical-JSON SHA-256
 * is recorded in the preregistration. The runner recomputes the digest and refuses on any
 * difference, so no rule here can drift after the operator signs, and none can fall back to a
 * tool default: the scanner's argv, environment, analyzer set, severity threshold, location rule
 * and normalisation are all read from here.
 */

import { canonicalJson, sha256Hex } from '../jev-judge/corpus.js';
import { INSERTION_TARGET, VARIANT_BLOCKS, VARIANT_IDS, type VariantId } from './variants.js';

export const SPECIMEN_PROTOCOL = 'cisco-skill-scanner-specimen-v1';

export interface FrozenConfig {
  protocol: string;
  preregistrationPath: string;
  approvalsPath: string;
  resultDir: string;
  resultStem: string;
  subject: {
    distribution: string;
    version: string;
    sourceRepository: string;
    sourceTag: string;
    sourceCommit: string;
    wheelFilename: string;
    wheelSha256: string;
    pythonVersion: string;
    lockfilePath: string;
    lockfileSha256: string;
    recordPrefixes: readonly string[];
    packageRecordSha256: string;
  };
  scan: {
    executable: string;
    argv: readonly string[];
    envAllowlist: readonly string[];
    locale: string;
    timeoutSeconds: number;
    analyzers: readonly string[];
  };
  corpus: {
    baseRepository: string;
    baseCommit: string;
    seed: string;
    baseCount: number;
    variants: readonly VariantId[];
    insertionTarget: string;
    variantBlocks: Readonly<Record<VariantId, readonly string[]>>;
  };
  scoring: {
    primaryRun: string;
    secondRun: string;
    detectSeverities: readonly string[];
    secondarySeverities: readonly string[];
    lineCoordinates: {
      bodyRelative: readonly { analyzer: string; ruleIdPrefix: string }[];
      matchRelative: readonly { analyzer: string; ruleIdPrefix: string }[];
    };
    normaliseRemove: readonly string[];
    cisco: {
      readmePath: string;
      readmeLines: string;
      coreOnlyRecall: number;
      coreCelRecall: number;
    };
  };
}

export const FROZEN: FrozenConfig = {
  protocol: SPECIMEN_PROTOCOL,
  preregistrationPath: 'docs/experiments/cisco-skill-scanner-preregistration-2026-10-01.md',
  approvalsPath: 'docs/experiments/cisco-skill-scanner-run-approvals-2026-10-01.md',
  resultDir: 'docs/experiments/cisco-skill-scanner-result-2026-10-01',
  resultStem: 'cisco-skill-scanner-result-2026-10-01',
  subject: {
    distribution: 'cisco-ai-skill-scanner',
    version: '2.1.0',
    sourceRepository: 'https://github.com/cisco-ai-defense/skill-scanner',
    sourceTag: '2.1.0',
    sourceCommit: 'a24df340ca6056a6446a239f4a7b114b11c6073a',
    wheelFilename:
      'cisco_ai_skill_scanner-2.1.0-cp311.cp312.cp313.cp314-none-macosx_13_0_arm64.whl',
    wheelSha256: '452811a64399a7f5f6656f5fccb5487a5f3a0ca00e8cdfa484761022da852bf6',
    pythonVersion: '3.12.13 (main, Mar  3 2026, 12:39:30) [Clang 21.0.0 (clang-2100.0.123.102)]',
    lockfilePath: 'packages/bede/src/skill-scanner-specimen/requirements.lock.txt',
    lockfileSha256: 'f7e8a7dfa0abae20d0eb83a88ae4fe2fdf3a65c17340e14563fbe5ae01bc5b5d',
    recordPrefixes: ['skill_scanner/'],
    packageRecordSha256: 'fe09408eeb9f99097882300515b5f1e2f6af14aa1fe75cc39a3f519207c5de87',
  },
  scan: {
    executable: 'skill-scanner',
    argv: ['scan', '{skillDir}', '--format', 'json'],
    envAllowlist: ['HOME', 'LANG', 'PATH', 'TMPDIR'],
    locale: 'en_US.UTF-8',
    timeoutSeconds: 600,
    analyzers: ['static_analyzer', 'bytecode', 'pipeline', 'correlation'],
  },
  corpus: {
    baseRepository: 'https://github.com/alirezarezvani/claude-skills',
    baseCommit: '19392f7a08264ed00486a251f5b2098321771f94',
    seed: 'cisco-skill-scanner-specimen-2026-10-01',
    baseCount: 80,
    variants: [...VARIANT_IDS],
    insertionTarget: INSERTION_TARGET,
    variantBlocks: VARIANT_BLOCKS,
  },
  scoring: {
    primaryRun: 'run-1',
    secondRun: 'run-2',
    detectSeverities: ['CRITICAL', 'HIGH'],
    secondarySeverities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    lineCoordinates: {
      // Reported line counts from the first line after the frontmatter: YARA over the instruction
      // body (static.py:4541, yara_scanner.py:269) and pipeline compound sequences
      // (pipeline_analyzer.py:1557, 1592). Physical line = reported line + the scanner's own body
      // offset (loader.py:337-346).
      bodyRelative: [
        { analyzer: 'static', ruleIdPrefix: 'YARA_' },
        { analyzer: 'pipeline', ruleIdPrefix: 'COMPOUND_' },
      ],
      // Reported line counts within the matched text (pipeline_analyzer.py:316, 700) and cannot be
      // converted; located by the finding's snippet occurring verbatim in the inserted block.
      matchRelative: [{ analyzer: 'pipeline', ruleIdPrefix: 'PIPELINE_TAINT_FLOW' }],
    },
    normaliseRemove: [
      'timestamp',
      'scan_duration_seconds',
      'duration_ms',
      'skill_path',
      'scan_metadata.cel.elapsed_ms',
      'scan_metadata.cel.projection_ms',
      'scan_metadata.cel.evaluation_ms',
    ],
    cisco: {
      readmePath: 'README.md',
      readmeLines: '47-49',
      coreOnlyRecall: 0.1988,
      coreCelRecall: 0.3143,
    },
  },
};

export function frozenConfigDigest(frozen: FrozenConfig = FROZEN): string {
  return sha256Hex(canonicalJson(frozen));
}
