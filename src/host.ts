/**
 * The host: builds and seals a transcript.
 *
 * The host holds `K_session` and therefore can mint any tag for any role. That
 * is not a flaw in the construction, it is the trust model: role separation
 * assumes a trusted host. Act 6's compromised-host control exercises exactly
 * this, and CLAIMS.yaml records it as `THREAT-1`.
 */
import { fromHex, toHex, ZERO32, ZERO_PREV } from './bytes.ts'
import { chainStep } from './chain.ts'
import { leafHash, PROTOCOL_VERSION, type Envelope, type Role } from './envelope.ts'
import { randomBytes } from './primitives.ts'
import { seal } from './seal.ts'
import { attest } from './attest.ts'
import type { SealedSegment, Transcript } from './verify.ts'

/** A mock tool: an Ed25519 keypair plus the name the agent pins it under. */
export interface ToolKeypair {
  name: string
  secretKey: Uint8Array
  publicKey: Uint8Array
}

export interface SegmentSpec {
  role: Role
  body: string
  tool?: string | null
  /**
   * Sign with this tool's key. Normally the tool named by `tool`; an explicit
   * value lets a fixture model a tool signing under a key the agent has not
   * pinned, or a stolen key signing as someone else.
   */
  signWith?: ToolKeypair | null
}

export class Host {
  readonly session: string
  readonly sessionBytes: Uint8Array
  readonly sessionKey: Uint8Array
  readonly pinned: Record<string, string> = {}
  private readonly segments: SealedSegment[] = []
  private head: Uint8Array = ZERO32

  constructor(sessionBytes: Uint8Array, sessionKey: Uint8Array) {
    if (sessionBytes.length !== 32) throw new Error('session_bytes must be 32 bytes')
    this.sessionBytes = sessionBytes
    this.session = toHex(sessionBytes)
    this.sessionKey = sessionKey
  }

  static random(): Host {
    return new Host(randomBytes(32), randomBytes(32))
  }

  static fromHexSeeds(sessionHex: string, sessionKeyHex: string): Host {
    return new Host(fromHex(sessionHex), fromHex(sessionKeyHex))
  }

  /** Pin a tool's public key, as the agent would at configuration time. */
  pin(tool: ToolKeypair): this {
    this.pinned[tool.name] = toHex(tool.publicKey)
    return this
  }

  async append(spec: SegmentSpec): Promise<SealedSegment> {
    const seq = this.segments.length
    const envelope: Envelope = {
      v: PROTOCOL_VERSION,
      session: this.session,
      seq,
      role: spec.role,
      tool: spec.tool ?? null,
      body: spec.body,
      prev: seq === 0 ? ZERO_PREV : toHex(this.head),
    }
    const leaf = await leafHash(envelope)
    this.head = await chainStep(this.head, leaf)

    const tag = toHex(await seal(this.sessionKey, this.sessionBytes, envelope.role, this.head))

    let sig: string | null = null
    let toolKey: string | null = null
    if (spec.signWith) {
      sig = toHex(await attest(spec.signWith.secretKey, this.session, seq, leaf))
      toolKey = spec.signWith.name
    }

    const sealed: SealedSegment = { envelope, tag, sig, tool_key: toolKey }
    this.segments.push(sealed)
    return sealed
  }

  transcript(): Transcript {
    return {
      v: PROTOCOL_VERSION,
      session: this.session,
      session_key: toHex(this.sessionKey),
      pinned_tool_keys: { ...this.pinned },
      // Deep copy so tamper controls cannot mutate the host's own state.
      segments: JSON.parse(JSON.stringify(this.segments)) as SealedSegment[],
    }
  }
}
