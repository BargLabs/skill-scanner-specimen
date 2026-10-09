/**
 * One full pass of the pinned scanner over the frozen corpus.
 *
 * Every frozen rule is enforced here, before and during the pass, and a departure refuses the
 * whole run rather than proceeding on a tool default:
 *
 *   before   the preregistration guard (`preregistration.ts`), the subject pin (`subject.ts`), the
 *            corpus digest and file set against the manifest (`corpus.ts`), and the manifest's
 *            case count against the frozen design;
 *   per case the scanner runs with the frozen argv, in an empty working directory, under an
 *            environment built from nothing but the frozen allowlist, so no API-key variable, no
 *            `.env` file in the working directory and no inherited configuration variable reaches
 *            it; the output's analyzer set must equal the frozen set exactly, or the run refuses.
 *
 * A case the scanner fails on is recorded under a named error status with its exit code and the
 * digest of its output; it is never dropped. Raw output is stored per case under the run
 * directory, which must lie outside the repository and is never committed.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { canonicalJson } from '../jev-judge/corpus.js';
import {
  type CorpusManifest,
  assertOutsideRepository,
  loadManifest,
  sha256,
  verifyCorpus,
} from './corpus.js';
import { type FrozenConfig, frozenConfigDigest } from './frozen.js';
import {
  type PreregistrationBinding,
  type PreregistrationGuardOptions,
  assertPreregistrationFrozen,
} from './preregistration.js';
import {
  type SubjectObservation,
  type SubjectPaths,
  type SubjectProbe,
  verifySubject,
} from './subject.js';
import { VARIANT_IDS } from './variants.js';

export const CASE_STATUSES = [
  'ok',
  'scanner_exit_nonzero',
  'scanner_timeout',
  'output_unparseable',
  'analyzer_failed',
] as const;
export type CaseStatus = (typeof CASE_STATUSES)[number];

export interface CaseRecord {
  caseId: string;
  status: CaseStatus;
  exitCode: number | null;
  stdoutSha256: string;
  stderrSha256: string;
  detail: string | null;
}

export interface RunRecord {
  protocol: string;
  label: string;
  frozenConfigDigest: string;
  harnessCommit: string;
  preregistration: PreregistrationBinding;
  subject: SubjectObservation;
  corpusDigest: string;
  caseCount: number;
  startedAt: string;
  finishedAt: string;
  cases: CaseRecord[];
}

export interface ScannerInvocation {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export type ScannerInvoker = (input: {
  executable: string;
  argv: string[];
  env: Record<string, string>;
  cwd: string;
  timeoutMs: number;
}) => ScannerInvocation;

export const spawnScanner: ScannerInvoker = ({ executable, argv, env, cwd, timeoutMs }) => {
  const result = spawnSync(executable, argv, {
    env,
    cwd,
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer: 1 << 28,
  });
  const timedOut = (result.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT';
  return {
    exitCode: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    timedOut,
  };
};

/** The environment the scanner sees: the frozen allowlist and nothing else. */
export function scannerEnv(
  frozen: FrozenConfig,
  venvDir: string,
  runDir: string,
): Record<string, string> {
  const values: Record<string, string> = {
    PATH: `${join(venvDir, 'bin')}:/usr/bin:/bin`,
    HOME: join(runDir, 'home'),
    TMPDIR: join(runDir, 'tmp'),
    LANG: frozen.scan.locale,
  };
  const keys = Object.keys(values).sort();
  const allowed = [...frozen.scan.envAllowlist].sort();
  if (canonicalJson(keys) !== canonicalJson(allowed)) {
    throw new Error(`not_run: scanner_env_differs_from_frozen:${keys.join(',')}`);
  }
  return values;
}

export function scannerArgv(frozen: FrozenConfig, skillDir: string): string[] {
  const argv = frozen.scan.argv.map((arg) => (arg === '{skillDir}' ? skillDir : arg));
  if (argv.filter((arg) => arg === skillDir).length !== 1) {
    throw new Error('not_run: scanner_argv_without_skill_dir');
  }
  return argv;
}

/** Status of one case from its invocation. Throws (refusing the run) on an analyzer-set departure. */
export function classifyInvocation(
  frozen: FrozenConfig,
  caseId: string,
  invocation: ScannerInvocation,
): { status: CaseStatus; detail: string | null } {
  if (invocation.timedOut) return { status: 'scanner_timeout', detail: null };
  if (invocation.exitCode !== 0) {
    return { status: 'scanner_exit_nonzero', detail: `exit=${invocation.exitCode}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(invocation.stdout);
  } catch {
    return { status: 'output_unparseable', detail: 'json_parse_failed' };
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    !Array.isArray((parsed as { findings?: unknown }).findings) ||
    !Array.isArray((parsed as { analyzers_used?: unknown }).analyzers_used)
  ) {
    return { status: 'output_unparseable', detail: 'shape' };
  }
  const result = parsed as { analyzers_used: unknown[]; analyzers_failed?: unknown[] };
  const used = [...result.analyzers_used].map(String).sort();
  const expected = [...frozen.scan.analyzers].sort();
  if (canonicalJson(used) !== canonicalJson(expected)) {
    throw new Error(`not_run: analyzer_set_differs_from_frozen:${caseId}:${used.join(',')}`);
  }
  if (Array.isArray(result.analyzers_failed) && result.analyzers_failed.length > 0) {
    return { status: 'analyzer_failed', detail: canonicalJson(result.analyzers_failed) };
  }
  return { status: 'ok', detail: null };
}

export function expectedCaseCount(frozen: FrozenConfig): number {
  return frozen.corpus.baseCount * (1 + VARIANT_IDS.length);
}

export function assertManifestMatchesDesign(manifest: CorpusManifest, frozen: FrozenConfig): void {
  if (manifest.frozenConfigDigest !== frozenConfigDigest(frozen)) {
    throw new Error('not_run: manifest_built_under_other_config');
  }
  const { bases, variants, cases } = manifest.counts;
  if (
    cases !== manifest.cases.length ||
    bases + variants !== cases ||
    cases !== expectedCaseCount(frozen) ||
    bases !== frozen.corpus.baseCount
  ) {
    throw new Error(
      `not_run: manifest_case_count:${bases}+${variants}=${cases}:${manifest.cases.length}`,
    );
  }
}

export interface RunOptions {
  repoRoot: string;
  corpusDir: string;
  runRoot: string;
  label: string;
  frozen: FrozenConfig;
  subjectPaths: SubjectPaths;
  invoker?: ScannerInvoker;
  probe?: SubjectProbe;
  guard?: PreregistrationGuardOptions;
  now?: () => Date;
}

export function runPass(options: RunOptions): RunRecord {
  const { repoRoot, corpusDir, runRoot, label, frozen, subjectPaths } = options;
  const now = options.now ?? (() => new Date());
  const digest = frozenConfigDigest(frozen);

  const preregistration = assertPreregistrationFrozen(
    repoRoot,
    frozen.preregistrationPath,
    digest,
    options.guard,
  );
  const dirty = spawnSync('git', ['status', '--porcelain'], {
    cwd: repoRoot,
    encoding: 'utf8',
  }).stdout.trim();
  if (dirty !== '') throw new Error('not_run: worktree_dirty');
  const subject = verifySubject(subjectPaths, frozen, options.probe);
  const manifest = loadManifest(corpusDir);
  verifyCorpus(corpusDir, manifest);
  assertManifestMatchesDesign(manifest, frozen);

  assertOutsideRepository(runRoot, repoRoot);
  const runDir = join(resolve(runRoot), label);
  if (existsSync(runDir)) throw new Error(`not_run: run_dir_exists:${runDir}`);
  for (const sub of ['raw', 'home', 'tmp', 'cwd'])
    mkdirSync(join(runDir, sub), { recursive: true });

  const env = scannerEnv(frozen, subjectPaths.venvDir, runDir);
  const executable = join(subjectPaths.venvDir, 'bin', frozen.scan.executable);
  const invoker = options.invoker ?? spawnScanner;
  const harnessCommit = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: repoRoot,
    encoding: 'utf8',
  }).stdout.trim();
  const startedAt = now().toISOString();
  const cases: CaseRecord[] = [];

  for (const c of manifest.cases) {
    const skillDir = resolve(corpusDir, c.skillDir);
    const invocation = invoker({
      executable,
      argv: scannerArgv(frozen, skillDir),
      env,
      cwd: join(runDir, 'cwd'),
      timeoutMs: frozen.scan.timeoutSeconds * 1000,
    });
    writeFileSync(join(runDir, 'raw', `${c.caseId}.json`), invocation.stdout);
    writeFileSync(join(runDir, 'raw', `${c.caseId}.stderr.txt`), invocation.stderr);
    const { status, detail } = classifyInvocation(frozen, c.caseId, invocation);
    cases.push({
      caseId: c.caseId,
      status,
      exitCode: invocation.exitCode,
      stdoutSha256: sha256(invocation.stdout),
      stderrSha256: sha256(invocation.stderr),
      detail,
    });
  }

  // The record's per-case digests are re-derived from the files on disk, not from memory: a
  // write that silently failed must not read as a recorded case.
  for (const record of cases) {
    const onDisk = sha256(readFileSync(join(runDir, 'raw', `${record.caseId}.json`), 'utf8'));
    if (onDisk !== record.stdoutSha256)
      throw new Error(`run_record_disagrees_with_disk:${record.caseId}`);
  }
  if (cases.length !== manifest.cases.length) {
    throw new Error(`run_case_count:${cases.length}:${manifest.cases.length}`);
  }

  const record: RunRecord = {
    protocol: frozen.protocol,
    label,
    frozenConfigDigest: digest,
    harnessCommit,
    preregistration,
    subject,
    corpusDigest: manifest.corpusDigest,
    caseCount: cases.length,
    startedAt,
    finishedAt: now().toISOString(),
    cases,
  };
  writeFileSync(join(runDir, 'run-record.json'), `${canonicalJson(record)}\n`);
  return record;
}

export function loadRunRecord(runRoot: string, label: string): RunRecord {
  const path = join(runRoot, label, 'run-record.json');
  if (!existsSync(path)) throw new Error(`not_run: run_record_absent:${path}`);
  return JSON.parse(readFileSync(path, 'utf8')) as RunRecord;
}
