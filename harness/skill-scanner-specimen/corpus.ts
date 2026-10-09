/**
 * Corpus construction and verification for the Cisco skill-scanner specimen.
 *
 * The corpus is built from git blobs at the pinned commit, never from a working tree, so a rebuild
 * from the same commit, seed and insertion texts is byte-for-byte identical. It is written to a
 * directory outside the repository and never committed or published; the manifest records a
 * digest per file and one digest over the whole corpus, and that digest is what the result
 * publishes.
 *
 * Layout under the corpus directory:
 *
 *   manifest.json
 *   cases/<caseId>/<base directory basename>/...   one skill directory per case
 *
 * `caseId` is `b<NN>` for a base and `b<NN>-<variant>` for a variant, `NN` the base's 1-based rank.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';

import { canonicalJson } from '../jev-judge/corpus.js';
import type { FrozenConfig } from './frozen.js';
import { frozenConfigDigest } from './frozen.js';
import { assertInert } from './inertness.js';
import { type SelectionResult, type TreeEntry, parseLsTree, selectBases } from './selection.js';
import { INSERTION_TARGET, VARIANT_IDS, type VariantId, insertVariant } from './variants.js';

export interface ManifestFile {
  path: string;
  mode: '100644' | '100755';
  sha256: string;
  bytes: number;
}

export interface ManifestCase {
  caseId: string;
  baseRank: number;
  basePath: string;
  variant: VariantId | null;
  /** Skill directory relative to the corpus directory. */
  skillDir: string;
  /** For a variant: the inserted file relative to the skill directory, and its 1-based line range. */
  insertedFile: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  files: ManifestFile[];
}

export interface CorpusManifest {
  protocol: string;
  frozenConfigDigest: string;
  baseRepository: string;
  baseCommit: string;
  seed: string;
  selection: {
    candidateCount: number;
    excludedCounts: Record<string, number>;
    eligibleCount: number;
    selected: SelectionResult['selected'];
  };
  counts: { bases: number; variants: number; cases: number };
  cases: ManifestCase[];
  corpusDigest: string;
}

export function sha256(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/** The source of git objects at the pinned commit. */
export interface GitObjectSource {
  listTree(commit: string): TreeEntry[];
  readBlob(oid: string): Buffer;
}

/**
 * Fetches exactly the pinned commit into `cacheDir` (a bare repository outside the working tree)
 * and returns an object source over it. Refuses if the fetched object is not that commit.
 */
export function fetchPinnedCommit(url: string, commit: string, cacheDir: string): GitObjectSource {
  const git = (args: readonly string[]): Buffer =>
    execFileSync('git', ['--git-dir', cacheDir, ...args], {
      maxBuffer: 1 << 30,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  if (!existsSync(join(cacheDir, 'HEAD'))) {
    mkdirSync(cacheDir, { recursive: true });
    execFileSync('git', ['init', '--bare', '--quiet', cacheDir]);
  }
  const has = (() => {
    try {
      return git(['cat-file', '-t', commit]).toString().trim() === 'commit';
    } catch {
      return false;
    }
  })();
  if (!has) git(['fetch', '--quiet', '--depth', '1', '--no-tags', url, commit]);
  const resolved = git(['rev-parse', `${commit}^{commit}`])
    .toString()
    .trim();
  if (resolved !== commit) {
    throw new Error(`not_run: base_commit_mismatch:expected=${commit}:fetched=${resolved}`);
  }
  return {
    listTree: (c) => parseLsTree(git(['ls-tree', '-r', '-z', c]).toString('utf8')),
    readBlob: (oid) => git(['cat-file', 'blob', oid]),
  };
}

function caseIdFor(rank: number, variant: VariantId | null): string {
  const base = `b${String(rank).padStart(2, '0')}`;
  return variant === null ? base : `${base}-${variant}`;
}

/** One line per file, sorted by corpus-relative path: `<path>\t<mode>\t<sha256>\n`. */
export function corpusDigestOf(cases: readonly ManifestCase[]): string {
  const lines = cases
    .flatMap((c) =>
      c.files.map((f) => `${posix.join(c.skillDir, f.path)}\t${f.mode}\t${f.sha256}\n`),
    )
    .sort();
  return sha256(lines.join(''));
}

export interface BuildCorpusOptions {
  source: GitObjectSource;
  frozen: FrozenConfig;
  outDir: string;
  /** The repository root; the build refuses to write inside it. */
  repoRoot: string;
  force?: boolean;
}

export function assertOutsideRepository(outDir: string, repoRoot: string): void {
  const rel = relative(resolve(repoRoot), resolve(outDir));
  if (rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))) {
    throw new Error(`not_run: corpus_dir_inside_repository:${outDir}`);
  }
}

export function buildCorpus(options: BuildCorpusOptions): CorpusManifest {
  const { source, frozen, outDir, repoRoot } = options;
  assertOutsideRepository(outDir, repoRoot);
  assertInert();
  if (existsSync(join(outDir, 'manifest.json')) && !options.force) {
    throw new Error(`not_run: corpus_exists:${outDir}`);
  }
  rmSync(join(outDir, 'cases'), { recursive: true, force: true });

  const tree = source.listTree(frozen.corpus.baseCommit);
  const selection = selectBases(tree, frozen.corpus.seed, frozen.corpus.baseCount);
  const cases: ManifestCase[] = [];

  for (const base of selection.selected) {
    const prefix = `${base.path}/`;
    const entries = tree
      .filter((e) => e.path.startsWith(prefix) && e.type === 'blob')
      .sort((a, b) => (a.path < b.path ? -1 : 1));
    const baseFiles = entries.map((e) => ({
      path: e.path.slice(prefix.length),
      mode: (e.mode === '100755' ? '100755' : '100644') as ManifestFile['mode'],
      content: source.readBlob(e.oid),
    }));
    const target = baseFiles.find((f) => f.path === INSERTION_TARGET);
    if (!target) throw new Error(`not_run: base_without_target:${base.path}`);
    const basename = base.path.split('/').pop() ?? base.path;

    for (const variant of [null, ...VARIANT_IDS] as const) {
      const caseId = caseIdFor(base.rank, variant);
      const skillDir = posix.join('cases', caseId, basename);
      let insertion: ReturnType<typeof insertVariant> | null = null;
      if (variant !== null) insertion = insertVariant(target.content.toString('utf8'), variant);
      const files: ManifestFile[] = [];
      for (const file of baseFiles) {
        const content =
          insertion !== null && file.path === INSERTION_TARGET
            ? Buffer.from(insertion.content, 'utf8')
            : file.content;
        const abs = join(outDir, skillDir, ...file.path.split('/'));
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, content);
        chmodSync(abs, file.mode === '100755' ? 0o755 : 0o644);
        files.push({
          path: file.path,
          mode: file.mode,
          sha256: sha256(content),
          bytes: content.length,
        });
      }
      cases.push({
        caseId,
        baseRank: base.rank,
        basePath: base.path,
        variant,
        skillDir,
        insertedFile: insertion === null ? null : INSERTION_TARGET,
        lineStart: insertion?.lineStart ?? null,
        lineEnd: insertion?.lineEnd ?? null,
        files,
      });
    }
  }

  const manifest: CorpusManifest = {
    protocol: frozen.protocol,
    frozenConfigDigest: frozenConfigDigest(frozen),
    baseRepository: frozen.corpus.baseRepository,
    baseCommit: frozen.corpus.baseCommit,
    seed: frozen.corpus.seed,
    selection: {
      candidateCount: selection.candidateCount,
      excludedCounts: Object.fromEntries(
        Object.entries(selection.excluded).map(([reason, dirs]) => [reason, dirs.length]),
      ),
      eligibleCount: selection.eligible.length,
      selected: selection.selected,
    },
    counts: {
      bases: cases.filter((c) => c.variant === null).length,
      variants: cases.filter((c) => c.variant !== null).length,
      cases: cases.length,
    },
    cases,
    corpusDigest: corpusDigestOf(cases),
  };
  writeFileSync(join(outDir, 'manifest.json'), `${canonicalJson(manifest)}\n`);
  return manifest;
}

export function loadManifest(corpusDir: string): CorpusManifest {
  const path = join(corpusDir, 'manifest.json');
  if (!existsSync(path)) throw new Error(`not_run: manifest_absent:${path}`);
  return JSON.parse(readFileSync(path, 'utf8')) as CorpusManifest;
}

function listFiles(dir: string, root = dir): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) return listFiles(abs, root);
    return [relative(root, abs).split(sep).join('/')];
  });
}

/**
 * Re-reads every file on disk and refuses unless the manifest's per-file digests, its corpus
 * digest, its file set, and the expected corpus digest all agree. A stray extra file refuses too:
 * the scanner reads the directory, not the manifest.
 */
export function verifyCorpus(
  corpusDir: string,
  manifest: CorpusManifest,
  expectedDigest?: string,
): void {
  const recomputed = corpusDigestOf(manifest.cases);
  if (recomputed !== manifest.corpusDigest) {
    throw new Error(
      `not_run: corpus_digest_mismatch:manifest_internal:${manifest.corpusDigest}:${recomputed}`,
    );
  }
  if (expectedDigest !== undefined && expectedDigest !== manifest.corpusDigest) {
    throw new Error(
      `not_run: corpus_digest_mismatch:expected=${expectedDigest}:manifest=${manifest.corpusDigest}`,
    );
  }
  const expectedFiles = new Set<string>();
  for (const c of manifest.cases) {
    for (const f of c.files) {
      const rel = posix.join(c.skillDir, f.path);
      expectedFiles.add(rel);
      const abs = join(corpusDir, ...rel.split('/'));
      if (!existsSync(abs)) throw new Error(`not_run: corpus_digest_mismatch:missing:${rel}`);
      const content = readFileSync(abs);
      if (sha256(content) !== f.sha256)
        throw new Error(`not_run: corpus_digest_mismatch:file:${rel}`);
      const executable = (statSync(abs).mode & 0o111) !== 0;
      if (executable !== (f.mode === '100755')) {
        throw new Error(`not_run: corpus_digest_mismatch:mode:${rel}`);
      }
    }
  }
  for (const rel of listFiles(join(corpusDir, 'cases'), corpusDir)) {
    if (!expectedFiles.has(rel)) throw new Error(`not_run: corpus_digest_mismatch:extra:${rel}`);
  }
}
