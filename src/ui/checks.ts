/**
 * Turning a VerifyResult into the six rows the verification panel shows.
 *
 * The grouping is by QUESTION rather than by segment, because "is the chain
 * intact?" is the thing a visitor is actually asking. The detail line always
 * names the specific failure code, so nothing is reduced to a generic
 * "invalid".
 */
import { FAILURE_NAMES, type FailureCode, type VerifyResult } from '../verify.ts'

export interface CheckRow {
  name: string
  /** What this check is asking, in plain language. */
  asks: string
  state: 'ok' | 'fail' | 'na'
  /** Failure codes owned by this row, if any fired. */
  codes: FailureCode[]
  detail: string
}

interface RowSpec {
  name: string
  asks: string
  owns: FailureCode[]
  okDetail: (r: VerifyResult) => string
}

const ROWS: RowSpec[] = [
  {
    name: 'Protocol version',
    asks: 'Is every envelope a version this verifier understands?',
    owns: ['V_REJECTED', 'MALFORMED'],
    okDetail: () => 'All segments declare v=1. Checked before any cryptography runs.',
  },
  {
    name: 'Session binding',
    asks: 'Does every segment belong to this conversation?',
    owns: ['SESSION_MISMATCH'],
    okDetail: (r) => `All ${r.segments.length} segments carry this session identifier.`,
  },
  {
    name: 'Sequence continuity',
    asks: 'Is anything missing, duplicated or out of order?',
    owns: ['SEQ_GAP'],
    okDetail: (r) => `seq 0 through ${Math.max(0, r.segments.length - 1)}, no gaps.`,
  },
  {
    name: 'Chain integrity',
    asks: 'Does each segment hash onto the one before it?',
    owns: ['CHAIN_BREAK'],
    okDetail: (r) => `Recomputed head H_${r.segments.length - 1} matches every stored prev link.`,
  },
  {
    name: 'Host seal (role-separated HMAC)',
    asks: 'Did the host seal this content, with this role, at this position?',
    owns: ['BAD_TAG', 'ROLE_MISMATCH'],
    okDetail: (r) => `${r.segments.length} tags verify under their own role key, and no other.`,
  },
  {
    name: 'Tool attestation (Ed25519)',
    asks: 'Did the pinned tool really emit these bytes?',
    owns: ['BAD_SIGNATURE', 'UNPINNED_TOOL'],
    okDetail: (r) => {
      const signed = r.segments.filter((s) => s.attestationOk !== null)
      const names = [...new Set(signed.map((s) => s.tool).filter(Boolean))].join(', ')
      return `${signed.length} signature${signed.length === 1 ? '' : 's'} verify against pinned key${
        signed.length === 1 ? '' : 's'
      }${names ? ` (${names})` : ''}.`
    },
  },
]

export function checkRows(r: VerifyResult): CheckRow[] {
  return ROWS.map((spec) => {
    const hits = r.findings.filter((f) => spec.owns.includes(f.code))
    if (hits.length > 0) {
      return {
        name: spec.name,
        asks: spec.asks,
        state: 'fail' as const,
        codes: [...new Set(hits.map((f) => f.code))],
        detail: hits
          .map((f) => (f.seq === null ? f.detail : `seq ${f.seq}: ${f.detail}`))
          .join(' · '),
      }
    }
    // A transcript with no signed segments makes no attestation claim, and
    // saying so is more honest than showing a green tick for a check that
    // never ran.
    if (spec.name.startsWith('Tool attestation')) {
      const signed = r.segments.filter((s) => s.attestationOk !== null)
      if (signed.length === 0) {
        return {
          name: spec.name,
          asks: spec.asks,
          state: 'na' as const,
          codes: [],
          detail: 'No segment in this transcript carries a tool signature. Nothing is claimed.',
        }
      }
    }
    return {
      name: spec.name,
      asks: spec.asks,
      state: 'ok' as const,
      codes: [],
      detail: spec.okDetail(r),
    }
  })
}

export function failureName(code: FailureCode): string {
  return FAILURE_NAMES[code]
}
