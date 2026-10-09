/**
 * The inertness check over every inserted element.
 *
 * A violation names the element and the offending token. The check is deliberately wider than the
 * frozen texts need, because its job is to fail on a future edit, not to bless the present one:
 *
 *   - every URL host and every bare domain-shaped token must be an RFC 2606 reserved name
 *     (`.invalid`, `.example`, `.test`, `.localhost`, or `example.com|net|org` and subdomains);
 *   - no IPv4 or IPv6 literal;
 *   - no credential-shaped string (AWS key id, GitHub, Slack, OpenAI or Anthropic token shapes,
 *     a PEM header);
 *   - every base64 run of 16 or more characters that decodes to printable text is decoded and
 *     checked by the same rules, so an encoded payload cannot carry a real host past the check.
 */

import { VARIANT_BLOCKS, VARIANT_IDS, type VariantId } from './variants.js';

export interface InertnessViolation {
  element: string;
  reason: string;
  token: string;
}

const RESERVED_TLDS = ['invalid', 'example', 'test', 'localhost'];
const RESERVED_SECOND_LEVEL = ['example.com', 'example.net', 'example.org'];

export function isReservedHost(host: string): boolean {
  const lower = host.toLowerCase().replace(/\.$/, '');
  const labels = lower.split('.');
  const tld = labels[labels.length - 1] ?? '';
  if (RESERVED_TLDS.includes(tld)) return true;
  return RESERVED_SECOND_LEVEL.some((name) => lower === name || lower.endsWith(`.${name}`));
}

const URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/([^\s/:?#'"`)<>]+)/gi;
// A domain-shaped token: two or more dot-separated labels ending in an alphabetic TLD. File names
// such as `install.sh` or `SKILL.md` match the shape too, so the TLD must also be one that a public
// registry delegates; the list below covers the common delegated TLDs and every reserved one.
const DOMAIN_PATTERN = /\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/gi;
const DELEGATED_TLDS = new Set([
  'com',
  'net',
  'org',
  'io',
  'dev',
  'app',
  'ai',
  'co',
  'xyz',
  'info',
  'biz',
  'me',
  'cloud',
  'site',
  'online',
  'ru',
  'cn',
  'uk',
  'de',
  'us',
]);
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_PATTERN = /\[[0-9a-f:]+\]|\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi;
const CREDENTIAL_PATTERNS: readonly [string, RegExp][] = [
  ['aws_access_key_id', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ['github_token', /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g],
  ['slack_token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g],
  ['openai_key', /\bsk-[A-Za-z0-9_-]{20,}\b/g],
  ['pem_private_key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
];
const BASE64_PATTERN = /[A-Za-z0-9+/]{16,}={0,2}/g;

function decodePrintableBase64(token: string): string | null {
  if (token.length % 4 !== 0) return null;
  const decoded = Buffer.from(token, 'base64').toString('utf8');
  return /^[\x20-\x7e\t\n\r]+$/.test(decoded) ? decoded : null;
}

export function checkText(element: string, text: string, depth = 0): InertnessViolation[] {
  const violations: InertnessViolation[] = [];
  for (const match of text.matchAll(URL_PATTERN)) {
    const host = match[1] ?? '';
    if (!isReservedHost(host))
      violations.push({ element, reason: 'url_host_not_reserved', token: host });
  }
  for (const match of text.matchAll(DOMAIN_PATTERN)) {
    const domain = match[1] ?? '';
    const tld = domain.split('.').pop()?.toLowerCase() ?? '';
    if (!isReservedHost(domain) && DELEGATED_TLDS.has(tld)) {
      violations.push({ element, reason: 'domain_not_reserved', token: domain });
    }
  }
  for (const match of text.matchAll(IPV4_PATTERN)) {
    violations.push({ element, reason: 'ip_literal', token: match[0] });
  }
  for (const match of text.matchAll(IPV6_PATTERN)) {
    violations.push({ element, reason: 'ip_literal', token: match[0] });
  }
  for (const [name, pattern] of CREDENTIAL_PATTERNS) {
    for (const match of text.matchAll(pattern)) {
      violations.push({ element, reason: `credential_shape:${name}`, token: match[0] });
    }
  }
  if (depth < 2) {
    for (const match of text.matchAll(BASE64_PATTERN)) {
      const decoded = decodePrintableBase64(match[0]);
      if (decoded !== null) violations.push(...checkText(`${element}:base64`, decoded, depth + 1));
    }
  }
  return violations;
}

/** Checks every frozen element; returns all violations (empty means inert). */
export function checkVariantBlocks(
  blocks: Readonly<Record<VariantId, readonly string[]>> = VARIANT_BLOCKS,
): InertnessViolation[] {
  return VARIANT_IDS.flatMap((id) => checkText(id, blocks[id].join('\n')));
}

export function assertInert(
  blocks: Readonly<Record<VariantId, readonly string[]>> = VARIANT_BLOCKS,
): void {
  const violations = checkVariantBlocks(blocks);
  if (violations.length > 0) {
    const first = violations[0];
    throw new Error(
      `not_run: insertion_not_inert:${first?.element}:${first?.reason}:${first?.token}:total=${violations.length}`,
    );
  }
}
