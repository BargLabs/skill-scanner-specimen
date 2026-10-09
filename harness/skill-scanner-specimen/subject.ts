/**
 * Verification of the pinned scanner installation, before any case is scanned.
 *
 * Five properties, each refusing on its own:
 *
 *   1. the hash-locked requirements file still hashes to the frozen digest;
 *   2. the cached wheel file hashes to the frozen wheel sha256 (the same digest the lockfile
 *      requires, so `pip install --require-hashes` could only have installed these bytes);
 *   3. the venv's interpreter reports the frozen `sys.version`;
 *   4. the installed distribution reports the frozen version;
 *   5. every file the installed RECORD lists under the package is re-hashed against its RECORD
 *      entry, and the sorted package lines of that RECORD hash to the frozen digest, which was read
 *      from the RECORD inside the pinned wheel at freeze. Installer-written lines (INSTALLER,
 *      REQUESTED, console scripts, `direct_url.json`) are outside the package prefix and excluded,
 *      so the digest does not depend on which installer ran.
 *
 * The check runs the venv's own interpreter on a fixed script with an empty environment; it makes
 * no network call.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { FrozenConfig } from './frozen.js';

export interface SubjectObservation {
  pythonVersion: string;
  packageVersion: string;
  packageRecordDigest: string;
  recordMismatches: string[];
}

/** Prints one JSON object. Reads only the installed distribution's own files. */
export const SUBJECT_PROBE = `
import base64, hashlib, importlib.metadata as md, json, pathlib, sys
dist = md.distribution(sys.argv[1])
prefixes = tuple(sys.argv[2].split(","))
root = pathlib.Path(dist.locate_file(""))
record = (pathlib.Path(dist._path) / "RECORD").read_text(encoding="utf-8")
lines = sorted(l for l in record.splitlines() if l.startswith(prefixes))
mismatches = []
for line in lines:
    path, digest, _size = line.rsplit(",", 2)
    algo, _, expected = digest.partition("=")
    actual = base64.urlsafe_b64encode(hashlib.new(algo, (root / path).read_bytes()).digest()).rstrip(b"=").decode()
    if actual != expected:
        mismatches.append(path)
print(json.dumps({
    "pythonVersion": sys.version,
    "packageVersion": dist.version,
    "packageRecordDigest": hashlib.sha256(("\\n".join(lines) + "\\n").encode()).hexdigest(),
    "recordMismatches": mismatches,
}))
`;

export function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export type SubjectProbe = (venvPython: string, frozen: FrozenConfig) => SubjectObservation;

export const runSubjectProbe: SubjectProbe = (venvPython, frozen) => {
  const out = execFileSync(
    venvPython,
    [
      '-I',
      '-c',
      SUBJECT_PROBE,
      frozen.subject.distribution,
      frozen.subject.recordPrefixes.join(','),
    ],
    { env: {}, encoding: 'utf8' },
  );
  return JSON.parse(out) as SubjectObservation;
};

export interface SubjectPaths {
  venvDir: string;
  wheelPath: string;
  lockfilePath: string;
}

export function venvPython(venvDir: string): string {
  return join(venvDir, 'bin', 'python');
}

export function verifySubject(
  paths: SubjectPaths,
  frozen: FrozenConfig,
  probe: SubjectProbe = runSubjectProbe,
): SubjectObservation {
  const s = frozen.subject;
  if (!existsSync(paths.lockfilePath)) throw new Error('not_run: lockfile_absent');
  const lockDigest = sha256File(paths.lockfilePath);
  if (lockDigest !== s.lockfileSha256) {
    throw new Error(
      `not_run: lockfile_digest_mismatch:expected=${s.lockfileSha256}:actual=${lockDigest}`,
    );
  }
  if (!readFileSync(paths.lockfilePath, 'utf8').includes(`--hash=sha256:${s.wheelSha256}`)) {
    throw new Error('not_run: lockfile_does_not_admit_pinned_wheel');
  }
  if (!existsSync(paths.wheelPath)) throw new Error('not_run: wheel_absent');
  const wheelDigest = sha256File(paths.wheelPath);
  if (wheelDigest !== s.wheelSha256) {
    throw new Error(
      `not_run: wheel_digest_mismatch:expected=${s.wheelSha256}:actual=${wheelDigest}`,
    );
  }
  const python = venvPython(paths.venvDir);
  if (!existsSync(python)) throw new Error('not_run: venv_absent');
  const observed = probe(python, frozen);
  if (observed.pythonVersion !== s.pythonVersion) {
    throw new Error(
      `not_run: python_version_mismatch:expected=${JSON.stringify(s.pythonVersion)}:actual=${JSON.stringify(observed.pythonVersion)}`,
    );
  }
  if (observed.packageVersion !== s.version) {
    throw new Error(
      `not_run: scanner_version_mismatch:expected=${s.version}:actual=${observed.packageVersion}`,
    );
  }
  if (observed.recordMismatches.length > 0) {
    throw new Error(
      `not_run: installed_files_differ_from_record:${observed.recordMismatches.length}:${observed.recordMismatches[0]}`,
    );
  }
  if (observed.packageRecordDigest !== s.packageRecordSha256) {
    throw new Error(
      `not_run: package_record_digest_mismatch:expected=${s.packageRecordSha256}:actual=${observed.packageRecordDigest}`,
    );
  }
  return observed;
}
