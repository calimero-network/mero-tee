/**
 * The five TDX measurement registers the verifier compares, what each records,
 * and how a quote's values are matched against a release's published lists.
 */

export const REGISTERS = ['mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3'];

export const PROFILES = ['debug', 'debug-read-only', 'locked-read-only'];

export const REGISTER_INFO = {
  mrtd: { label: 'MRTD', meaning: 'The TD’s initial firmware (TDVF), measured by the TDX module' },
  rtmr0: { label: 'RTMR0', meaning: 'Firmware configuration and machine shape' },
  rtmr1: { label: 'RTMR1', meaning: 'Boot path: the disk’s partition table and the kernel image (UKI)' },
  rtmr2: { label: 'RTMR2', meaning: 'The kernel image’s sections, including its command line (role, profile, root hash)' },
  rtmr3: { label: 'RTMR3', meaning: 'Extended once at boot with the image role, profile and root hash' },
};

export function normHex(v) {
  return typeof v === 'string' ? v.replace(/\s/g, '').replace(/^0x/i, '').toLowerCase() : '';
}

/**
 * The allowlist for a register in a policy object. Node releases
 * (`published-mrtds.json`) and agent policies name it `allowed_<reg>`; KMS
 * policies (`kms-attestation-policy.<profile>.json`) `kms_allowed_<reg>`.
 */
export function allowlistOf(policy, reg, kind) {
  if (!policy) return null;
  const keys = kind === 'kms' ? [`kms_allowed_${reg}`] : [`allowed_${reg}`];
  for (const k of keys) {
    if (Array.isArray(policy[k])) return policy[k];
  }
  return null;
}

/** Each register of `measurements` against `policy`'s list for it. */
export function compareRegisters(measurements, policy, kind) {
  return REGISTERS.map((reg) => {
    const actual = normHex(measurements?.[reg]) || null;
    const allowed = (allowlistOf(policy, reg, kind) || []).map(normHex).filter(Boolean);
    const match = Boolean(actual) && allowed.includes(actual);
    return { reg, actual, allowed, match };
  });
}

/** Profiles whose lists hold every register of `measurements`. */
export function fullyMatchingProfiles(measurements, policiesByProfile, kind) {
  return PROFILES.filter((p) => {
    const policy = policiesByProfile?.[p];
    return policy && compareRegisters(measurements, policy, kind).every((r) => r.match);
  });
}

/** The profile with the most matching registers (first in PROFILES order on a tie). */
export function closestProfile(measurements, policiesByProfile, kind) {
  let best = null;
  let bestScore = -1;
  for (const p of PROFILES) {
    const policy = policiesByProfile?.[p];
    if (!policy) continue;
    const score = compareRegisters(measurements, policy, kind).filter((r) => r.match).length;
    if (score > bestScore) {
      best = p;
      bestScore = score;
    }
  }
  return best;
}

export function hasAnyPolicy(policiesByProfile) {
  return Boolean(policiesByProfile) && Object.values(policiesByProfile).some(Boolean);
}

/** Registers where Intel's claims and the quote parse both have a value and differ. */
export function itaDisagreements(quoteRtmrs, itaRtmrs) {
  if (!quoteRtmrs || !itaRtmrs) return [];
  return REGISTERS.filter((k) => {
    const q = normHex(quoteRtmrs[k]);
    const i = normHex(itaRtmrs[k]);
    return q && i && q !== i;
  });
}
