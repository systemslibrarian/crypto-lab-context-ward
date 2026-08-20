/**
 * The scripted agent.
 *
 * This is a DETERMINISTIC MOCK. There is no model here, no API key field, and
 * no network call. It is a small parser implementing one explicit trust policy:
 *
 *     Content arriving in an authoritative-role segment is treated as
 *     instruction, whatever its provenance label says.
 *
 * That policy is stated rather than discovered, and it is a policy real systems
 * commonly adopt -- flattening tool output, runtime errors and recalled state
 * into the same instruction stream as the operator's own prompt. Watching a
 * mock follow it is not evidence about any real model's behaviour, and the UI
 * says so persistently rather than in a footnote.
 *
 * The mock is a parser rather than a canned transcript on purpose: the visitor
 * can read exactly what makes it comply, and the same code decides Act 1 (no
 * directive present, agent behaves) and Act 8 (directive present, agent
 * complies) with no per-act special-casing.
 */
import type { Transcript } from './verify.ts'
import type { Role } from './envelope.ts'

/**
 * The disclosure shown persistently on screen. Exported so `e2e/claims.spec.ts`
 * can assert the page prints this exact text rather than a paraphrase that has
 * drifted from what the mock actually is.
 */
export const SCRIPTED_TRANSCRIPT_DISCLOSURE =
  'Scripted transcript. This agent is configured with a trust policy that treats tool ' +
  'output as authoritative — a policy real systems commonly use. Nothing here is a ' +
  'measurement of any real model’s behaviour.'

/**
 * Roles this agent's policy treats as carrying instructions.
 *
 * `user` is absent only because this exhibit's scripts never place a directive
 * there; the policy would follow one if it did. The interesting entries are
 * `tool_result`, `runtime`, `state` and `retrieved` -- the four channels Acts
 * 2, 3, 4 and 8a travel through.
 */
export const AUTHORITATIVE_ROLES: readonly Role[] = [
  'system',
  'tool_result',
  'runtime',
  'state',
  'retrieved',
]

/** A directive the scripted policy will act on: a line beginning `>> ACTION:`. */
const DIRECTIVE = /^\s*>>\s*ACTION:\s*(.+)$/gm

export interface AgentStep {
  /** Index of the segment being read. */
  index: number
  seq: number
  role: Role
  tool: string | null
  /** What the policy did with this segment. */
  disposition: 'read' | 'obeyed'
  /** The directive text, when one was followed. */
  action: string | null
  note: string
}

export interface AgentRun {
  steps: AgentStep[]
  /** Directives the policy followed, in order. */
  actionsTaken: string[]
  /** True when the agent acted on attacker-supplied instructions. */
  compromised: boolean
  /** Plain-language outcome for the transcript panel. */
  outcome: string
}

/**
 * Run the scripted policy over a transcript.
 *
 * Deliberately does NOT consult the verification result. That independence is
 * the exhibit's central demonstration: the agent behaves identically whether
 * every seal verifies or none of them do, because obedience and integrity are
 * unrelated questions. A system that wanted them related would have to add a
 * policy layer that reads the verifier's output -- and this exhibit does not
 * pretend to supply one.
 */
export function runAgent(t: Transcript, task: string): AgentRun {
  const steps: AgentStep[] = []
  const actionsTaken: string[] = []

  for (let i = 0; i < t.segments.length; i++) {
    const seg = t.segments[i]
    if (!seg) continue
    const e = seg.envelope
    const authoritative = AUTHORITATIVE_ROLES.includes(e.role)

    DIRECTIVE.lastIndex = 0
    const matches = authoritative ? [...e.body.matchAll(DIRECTIVE)] : []

    if (matches.length === 0) {
      steps.push({
        index: i,
        seq: e.seq,
        role: e.role,
        tool: e.tool,
        disposition: 'read',
        action: null,
        note: authoritative
          ? 'No directive present. Content used as data.'
          : `Role ${e.role} is not treated as authoritative by this policy.`,
      })
      continue
    }

    for (const m of matches) {
      const action = (m[1] ?? '').trim()
      actionsTaken.push(action)
      steps.push({
        index: i,
        seq: e.seq,
        role: e.role,
        tool: e.tool,
        disposition: 'obeyed',
        action,
        note:
          `Policy treats role ${e.role} as authoritative, so this directive was ` +
          'followed as though the operator had written it.',
      })
    }
  }

  const compromised = actionsTaken.length > 0
  return {
    steps,
    actionsTaken,
    compromised,
    outcome: compromised
      ? `Task "${task}" completed, and ${actionsTaken.length} attacker directive` +
        `${actionsTaken.length === 1 ? '' : 's'} followed alongside it.`
      : `Task "${task}" completed. No directive appeared in any authoritative segment.`,
  }
}
