/**
 * Deterministic material for the scripted scenarios.
 *
 * Every seed here is a fixed constant so that a given act produces byte-identical
 * envelopes on every run, in every browser, and in `tools/gen-fixtures.ts`. The
 * committed fixtures in `/fixtures` are therefore reproducible, and
 * `verification/verify.py` checks the same bytes a visitor sees in the inspector.
 *
 * These are TEST KEYS, published in a public repository. They protect nothing.
 */
import { fromHex } from '../bytes.ts'
import { ed25519PublicKey } from '../primitives.ts'
import { Host, type ToolKeypair } from '../host.ts'

export const SEEDS = {
  session: '5b1f3a90c4d27e6188aa02cf4713d5e9b62047ac1e8f35d0729c6ab4f0e1d3c8',
  sessionKey: 'a17c02e59d4b8f36c1207ae43f9b5d8021c6e7f40a93b8d25e17c40fb69a3d15',
  priorSession: '0c94e7b21d6a58f3402ebc7159d83a06f47b1e25c930d8a6b14f7e0328c5d9b7',
  priorSessionKey: '6e2d70b419a8c53f0d17e492bc6a3f851920de74c38b5a0f6d29e18c47b03fa5',
  toolTicketDb: '11111111111111111111111111111111111111111111111111111111111111a1',
  toolWebFetch: '22222222222222222222222222222222222222222222222222222222222222b2',
  toolInvoiceApi: '33333333333333333333333333333333333333333333333333333333333333c3',
} as const

async function keypair(name: string, seedHex: string): Promise<ToolKeypair> {
  const secretKey = fromHex(seedHex)
  return { name, secretKey, publicKey: await ed25519PublicKey(secretKey) }
}

export interface Kit {
  ticketDb: ToolKeypair
  webFetch: ToolKeypair
  invoiceApi: ToolKeypair
}

let cached: Promise<Kit> | null = null

export function kit(): Promise<Kit> {
  cached ??= (async () => ({
    ticketDb: await keypair('ticket_db', SEEDS.toolTicketDb),
    webFetch: await keypair('web_fetch', SEEDS.toolWebFetch),
    invoiceApi: await keypair('invoice_api', SEEDS.toolInvoiceApi),
  }))()
  return cached
}

/** A host seeded from the fixed session constants, with all three tools pinned. */
export async function seededHost(
  session: string = SEEDS.session,
  sessionKey: string = SEEDS.sessionKey,
): Promise<Host> {
  const k = await kit()
  return Host.fromHexSeeds(session, sessionKey).pin(k.ticketDb).pin(k.webFetch).pin(k.invoiceApi)
}
