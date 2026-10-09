/**
 * The preregistration guard for the Cisco skill-scanner specimen.
 *
 * Four properties, each refusing on its own:
 *
 *   1. the commit that FIRST ADDED the preregistration is an ancestor of HEAD (or HEAD itself: the
 *      operator's signed commit may be the tip when a run starts);
 *   2. that commit carries a good signature (`%G?` = `G`), because in this repository a signed
 *      commit on an authority path is the operator's decision, and an unsigned one is a draft;
 *   3. the working file still hashes to its blob at that commit, and no later commit touched it;
 *   4. the frozen-configuration digest the document records equals the digest of the harness's
 *      frozen configuration, so harness and document are bound by content, not by commit order
 *      (phase 1 commits the harness before the operator signs the document).
 *
 * The first-add commit is used rather than the latest so a later touch cannot move the freeze.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface PreregistrationBinding {
  path: string;
  commit: string;
  blob: string;
  recordedConfigDigest: string;
}

export interface PreregistrationGuardOptions {
  /** Tests build unsigned fixture histories; the CLI never disables this. */
  requireSignature?: boolean;
}

export const CONFIG_DIGEST_PATTERN =
  /Frozen harness configuration digest \(SHA-256\): `([a-f0-9]{64})`/;

function git(repoRoot: string, args: readonly string[]): string {
  return execFileSync('git', args, { cwd: repoRoot, encoding: 'utf8' }).trim();
}

export function assertPreregistrationFrozen(
  repoRoot: string,
  path: string,
  expectedConfigDigest: string,
  options: PreregistrationGuardOptions = {},
): PreregistrationBinding {
  const requireSignature = options.requireSignature ?? true;
  const history = git(repoRoot, ['log', '--format=%H', '--', path]).split('\n').filter(Boolean);
  const head = git(repoRoot, ['rev-parse', 'HEAD']);
  const firstAdd = git(repoRoot, ['log', '--reverse', '--diff-filter=A', '--format=%H', '--', path])
    .split('\n')
    .find(Boolean);
  if (!firstAdd) {
    // Searching HEAD's history alone would make "committed elsewhere, not under this harness"
    // indistinguishable from "never committed"; the two are different refusals.
    const elsewhere = git(repoRoot, [
      'log',
      '--all',
      '--reverse',
      '--diff-filter=A',
      '--format=%H',
      '--',
      path,
    ])
      .split('\n')
      .find(Boolean);
    if (elsewhere) throw new Error(`not_run: preregistration_not_ancestor:${elsewhere}:${head}`);
    throw new Error('not_run: preregistration_not_ancestor:never_committed');
  }

  const ancestry = spawnSync('git', ['merge-base', '--is-ancestor', firstAdd, head], {
    cwd: repoRoot,
  });
  if (ancestry.status !== 0) {
    throw new Error(`not_run: preregistration_not_ancestor:${firstAdd}:${head}`);
  }

  if (requireSignature) {
    const status = git(repoRoot, ['log', '-1', '--format=%G?', firstAdd]);
    if (status !== 'G') {
      throw new Error(`not_run: preregistration_unsigned:${firstAdd}:status=${status}`);
    }
  }

  if (history.length !== 1 || history[0] !== firstAdd) {
    throw new Error(`not_run: preregistration_modified_after_freeze:commits=${history.length}`);
  }
  const blob = git(repoRoot, ['rev-parse', `${firstAdd}:${path}`]);
  const working = git(repoRoot, ['hash-object', path]);
  if (blob !== working) {
    throw new Error(
      `not_run: preregistration_modified_after_freeze:frozen=${blob}:working=${working}`,
    );
  }

  const text = readFileSync(join(repoRoot, path), 'utf8');
  const recorded = CONFIG_DIGEST_PATTERN.exec(text)?.[1];
  if (!recorded) throw new Error('not_run: preregistration_config_digest_absent');
  if (recorded !== expectedConfigDigest) {
    throw new Error(
      `not_run: frozen_config_differs_from_preregistration:recorded=${recorded}:harness=${expectedConfigDigest}`,
    );
  }
  return { path, commit: firstAdd, blob, recordedConfigDigest: recorded };
}
