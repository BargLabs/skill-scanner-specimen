/**
 * `pnpm --filter @alfred/bede experiment:skill-scanner-specimen build [--force]`
 * `pnpm --filter @alfred/bede experiment:skill-scanner-specimen run --label run-1|run-2`
 * `pnpm --filter @alfred/bede experiment:skill-scanner-specimen score`
 *
 * Optional on every subcommand: `--home <dir>` (default `~/.cache/alfred-cisco-specimen`), under
 * which the corpus (`corpus/`), the base-repository object cache (`claude-skills.git`), the runs
 * (`runs/`), the venv (`venv/`) and the pinned wheel live. All of them are outside the repository
 * and none is ever committed.
 *
 * `build` fetches exactly the pinned base commit, applies the frozen selection rule and writes the
 * 80 bases and 400 variants with their manifest. `run` makes one full pass of the pinned scanner.
 * `score` reads both passes, scores the frozen rule and writes the result JSON and Markdown under
 * `docs/experiments/cisco-skill-scanner-result-2026-10-01/`.
 *
 * Every subcommand first runs the preregistration guard: the preregistration must be committed,
 * signed, unmodified, an ancestor of HEAD, and record this harness's frozen-configuration digest.
 *
 * Any `not_run:` refusal exits 3 with the reason on stderr and writes no result file, so a refusal
 * is never mistakable for a crash (exit 1) or a success (exit 0).
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { bodyOffsetsFor } from './bodyoffsets.js';
import { buildCorpus, fetchPinnedCommit, loadManifest, verifyCorpus } from './corpus.js';
import { FROZEN, frozenConfigDigest } from './frozen.js';
import { assertPreregistrationFrozen } from './preregistration.js';
import { assertMarkdownMatchesJson, renderPublication } from './publish.js';
import { assertManifestMatchesDesign, loadRunRecord, runPass } from './run.js';
import { rawReader, score } from './score.js';
import { type SubjectPaths, venvPython, verifySubject } from './subject.js';

interface Options {
  command: 'build' | 'run' | 'score' | 'frozen-digest' | 'rebuild-digest';
  home: string;
  label: string | undefined;
  force: boolean;
}

function parseArgs(args: readonly string[]): Options {
  const [command, ...rest] = args;
  if (
    command !== 'build' &&
    command !== 'run' &&
    command !== 'score' &&
    command !== 'frozen-digest' &&
    command !== 'rebuild-digest'
  ) {
    throw new Error(`not_run: unknown_subcommand:${command ?? '(none)'}`);
  }
  const options: Options = {
    command,
    home: join(homedir(), '.cache', 'alfred-cisco-specimen'),
    label: undefined,
    force: false,
  };
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === '--home') options.home = resolve(rest[++i] ?? '');
    else if (arg === '--label') options.label = rest[++i];
    else if (arg === '--force') options.force = true;
    else throw new Error(`not_run: unknown_argument:${arg}`);
  }
  return options;
}

function repoRoot(): string {
  return execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
}

function subjectPaths(home: string, root: string): SubjectPaths {
  return {
    venvDir: join(home, 'venv'),
    wheelPath: join(home, FROZEN.subject.wheelFilename),
    lockfilePath: join(root, FROZEN.subject.lockfilePath),
  };
}

function main(args: readonly string[]): void {
  const options = parseArgs(args);
  const root = repoRoot();
  const digest = frozenConfigDigest(FROZEN);
  const corpusDir = join(options.home, 'corpus');
  const runRoot = join(options.home, 'runs');

  // Read-only verification entry points for scripts/check-result-pr-provenance.mjs (#2415): the
  // built corpus is never committed (preregistration), so a result's corpusDigest is checked by
  // rebuilding it from the pinned public commit with this, the base branch's, harness. Each
  // prints one JSON line and writes nothing outside a fresh temporary directory.
  if (options.command === 'frozen-digest') {
    process.stdout.write(`${JSON.stringify({ frozenConfigDigest: digest })}\n`);
    return;
  }
  if (options.command === 'rebuild-digest') {
    assertPreregistrationFrozen(root, FROZEN.preregistrationPath, digest);
    const scratch = mkdtempSync(join(tmpdir(), 'cisco-specimen-rebuild-'));
    try {
      const source = fetchPinnedCommit(
        `${FROZEN.corpus.baseRepository}.git`,
        FROZEN.corpus.baseCommit,
        join(scratch, 'claude-skills.git'),
      );
      const outDir = join(scratch, 'corpus');
      mkdirSync(outDir, { recursive: true });
      const manifest = buildCorpus({
        source,
        frozen: FROZEN,
        outDir,
        repoRoot: root,
        force: false,
      });
      verifyCorpus(outDir, manifest);
      assertManifestMatchesDesign(manifest, FROZEN);
      process.stdout.write(
        `${JSON.stringify({ frozenConfigDigest: digest, corpusDigest: manifest.corpusDigest, cases: manifest.counts.cases })}\n`,
      );
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
    return;
  }

  if (options.command === 'build') {
    assertPreregistrationFrozen(root, FROZEN.preregistrationPath, digest);
    const source = fetchPinnedCommit(
      `${FROZEN.corpus.baseRepository}.git`,
      FROZEN.corpus.baseCommit,
      join(options.home, 'claude-skills.git'),
    );
    mkdirSync(corpusDir, { recursive: true });
    const manifest = buildCorpus({
      source,
      frozen: FROZEN,
      outDir: corpusDir,
      repoRoot: root,
      force: options.force,
    });
    verifyCorpus(corpusDir, manifest);
    assertManifestMatchesDesign(manifest, FROZEN);
    process.stdout.write(
      `built ${manifest.counts.cases} cases (${manifest.counts.bases} bases, ${manifest.counts.variants} variants) read back from the manifest; corpus digest ${manifest.corpusDigest}\n`,
    );
    return;
  }

  if (options.command === 'run') {
    const label = options.label;
    if (label !== FROZEN.scoring.primaryRun && label !== FROZEN.scoring.secondRun) {
      throw new Error(`not_run: run_label_not_frozen:${label ?? '(none)'}`);
    }
    const record = runPass({
      repoRoot: root,
      corpusDir,
      runRoot,
      label,
      frozen: FROZEN,
      subjectPaths: subjectPaths(options.home, root),
    });
    const counts: Record<string, number> = {};
    for (const c of record.cases) counts[c.status] = (counts[c.status] ?? 0) + 1;
    process.stdout.write(`${label}: ${record.caseCount} cases ${JSON.stringify(counts)}\n`);
    return;
  }

  assertPreregistrationFrozen(root, FROZEN.preregistrationPath, digest);
  const paths = subjectPaths(options.home, root);
  verifySubject(paths, FROZEN);
  const manifest = loadManifest(corpusDir);
  verifyCorpus(corpusDir, manifest);
  assertManifestMatchesDesign(manifest, FROZEN);
  const first = {
    record: loadRunRecord(runRoot, FROZEN.scoring.primaryRun),
    raw: rawReader(runRoot, FROZEN.scoring.primaryRun),
  };
  const second = {
    record: loadRunRecord(runRoot, FROZEN.scoring.secondRun),
    raw: rawReader(runRoot, FROZEN.scoring.secondRun),
  };
  const bodyOffsets = bodyOffsetsFor(manifest, corpusDir, venvPython(paths.venvDir));
  const result = score({
    frozen: FROZEN,
    frozenConfigDigest: digest,
    manifest,
    bodyOffsets,
    first,
    second,
  });
  const publication = renderPublication(result, {
    frozen: FROZEN,
    manifest,
    runs: [first.record, second.record],
  });
  assertMarkdownMatchesJson(publication);
  const outDir = join(root, FROZEN.resultDir);
  const jsonPath = join(outDir, `${FROZEN.resultStem}.json`);
  const mdPath = join(outDir, `${FROZEN.resultStem}.md`);
  if ((existsSync(jsonPath) || existsSync(mdPath)) && !options.force) {
    throw new Error(`not_run: result_exists:${outDir}`);
  }
  mkdirSync(outDir, { recursive: true });
  writeFileSync(jsonPath, publication.json);
  writeFileSync(mdPath, publication.markdown);
  process.stdout.write(`wrote ${jsonPath} and ${mdPath}\n`);
}

try {
  main(process.argv.slice(2));
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(message.startsWith('not_run:') ? 3 : 1);
}
