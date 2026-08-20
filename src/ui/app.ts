/**
 * The exhibit's UI.
 *
 * Two depths, per the brief:
 *   "Demo"     -- the guided acts, provenance labels, tamper controls
 *   "Full lab" -- adds the byte-level envelope inspector, the enc() breakdown
 *                 and the raw sealed transcript
 *
 * Content from a transcript is only ever inserted with `textContent`. See
 * `src/ui/dom.ts`.
 */
import { clear, el, short } from './dom.ts'
import { checkRows, failureName } from './checks.ts'
import { buildActs, type Act } from '../acts/index.ts'
import { verifyTranscript, type SealedSegment, type Transcript, type VerifyResult } from '../verify.ts'
import { runAgent, SCRIPTED_TRANSCRIPT_DISCLOSURE, type AgentRun } from '../agent-mock.ts'
import { leafHashHex, type Envelope } from '../envelope.ts'
import { enc, toHex } from '../bytes.ts'
import type { TamperControl } from '../tamper.ts'

type Mode = 'demo' | 'lab'

interface State {
  acts: Act[]
  actIndex: number
  mode: Mode
  activeTamper: string | null
}

const ROLE_LABEL: Record<string, string> = {
  system: 'SYSTEM',
  user: 'USER',
  tool_result: 'TOOL_RESULT',
  runtime: 'RUNTIME',
  state: 'STATE',
  retrieved: 'RETRIEVED',
}

/** Split a body into runs so directive lines can be marked without innerHTML. */
function bodyNodes(body: string): Node[] {
  const out: Node[] = []
  const lines = body.split('\n')
  lines.forEach((line, i) => {
    const suffix = i < lines.length - 1 ? '\n' : ''
    if (/^\s*>>\s*ACTION:/.test(line)) {
      out.push(el('span', { class: 'ward-directive' }, [line]))
      if (suffix) out.push(document.createTextNode(suffix))
    } else {
      out.push(document.createTextNode(line + suffix))
    }
  })
  return out
}

// ---------------------------------------------------------------------------
// Persistent chrome
// ---------------------------------------------------------------------------

function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title' }, ['Context Ward']),
      el('p', { class: 'cl-hero-sub' }, ['SHA-256 hash chain · HMAC-SHA-256 · Ed25519']),
      el('p', { class: 'cl-hero-desc' }, [
        'Seals each segment of an agent’s context window into a hash chain with a ' +
          'role-separated HMAC and an Ed25519 tool signature, then lets you tamper with it ' +
          'and watch which attacks the cryptography names and which it cannot see at all.',
      ]),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label' }, ['WHY IT MATTERS']),
      el('p', { class: 'cl-hero-why-text' }, [
        'Agents read tool output, error strings and their own saved notes as if all of it were ' +
          'trustworthy. Cryptography can prove where each piece came from and that nobody edited ' +
          'it in transit. It cannot make any of that safe to obey, and the difference is where ' +
          'real systems get breached.',
      ]),
    ]),
  ])
}

function disclosure(): HTMLElement {
  return el('section', { class: 'ward-disclosure', role: 'note', 'aria-label': 'Scope of this demonstration' }, [
    el('span', { class: 'ward-disclosure-tag' }, ['MOCK']),
    el('p', {}, [SCRIPTED_TRANSCRIPT_DISCLOSURE]),
  ])
}

function threeQuestions(): HTMLElement {
  const q = (question: string, answer: string, answered: 'yes' | 'no') =>
    el('li', { class: 'ward-question', 'data-answered': answered }, [
      el('span', { class: 'ward-question-q' }, [question]),
      el('span', { class: 'ward-question-a' }, [answer]),
    ])

  return el('ul', { class: 'ward-questions', 'aria-label': 'What each layer can answer' }, [
    q('Was this context altered?', 'ANSWERED — hash chain, HMAC seal', 'yes'),
    q('Who supplied it?', 'ANSWERED — Ed25519 tool attestation', 'yes'),
    q('Should the model obey it?', 'NOT ANSWERED — nothing here can', 'no'),
  ])
}

// ---------------------------------------------------------------------------
// Panels
// ---------------------------------------------------------------------------

function panel(title: string, headExtra: Node | null, body: Node[]): HTMLElement {
  return el('section', { class: 'ward-panel' }, [
    el('div', { class: 'ward-panel-head' }, [
      el('h3', { class: 'ward-panel-title' }, [title]),
      headExtra,
    ]),
    el('div', { class: 'ward-panel-body' }, body),
  ])
}

function sourceBadge(role: string): HTMLElement {
  return el('span', { class: 'ward-source', 'data-role': role }, [
    `SOURCE: ${ROLE_LABEL[role] ?? role.toUpperCase()}`,
  ])
}

function fieldsTable(e: Envelope, leaf: string, chain: string): HTMLElement {
  const row = (field: string, value: string, covered: 'leaf' | 'mirror') =>
    el('tr', {}, [
      el('th', { scope: 'row' }, [field]),
      el('td', {}, [value]),
      el('td', {}, [
        el('span', { class: 'ward-covered', 'data-covered': covered }, [
          covered === 'leaf' ? 'in leaf' : 'mirror',
        ]),
      ]),
    ])

  return el('div', { class: 'ward-scroll', tabindex: '0', role: 'group', 'aria-label': 'Envelope fields' }, [
    el('table', { class: 'ward-fields' }, [
      el('caption', {}, [
        'Every field is covered by leaf_n except prev, which mirrors the previous chain hash ' +
          'and is checked against an independent recomputation.',
      ]),
      el('tbody', {}, [
        row('v', String(e.v), 'leaf'),
        row('session', short(e.session) + '…', 'leaf'),
        row('seq', String(e.seq), 'leaf'),
        row('role', e.role, 'leaf'),
        row('tool', e.tool ?? '(null)', 'leaf'),
        row('body', `${enc(e.body).length - 4} bytes`, 'leaf'),
        row('prev', short(e.prev) + '…', 'mirror'),
        el('tr', {}, [
          el('th', { scope: 'row' }, ['leaf_n']),
          el('td', {}, [short(leaf) + '…']),
          el('td', {}, ['']),
        ]),
        el('tr', {}, [
          el('th', { scope: 'row' }, ['H_n']),
          el('td', {}, [short(chain) + '…']),
          el('td', {}, ['']),
        ]),
      ]),
    ]),
  ])
}

function transcriptPanel(
  t: Transcript,
  result: VerifyResult,
  act: Act,
  mode: Mode,
): HTMLElement {
  const items = t.segments.map((seg: SealedSegment, i) => {
    const e = seg.envelope
    const seg_result = result.segments[i]
    const isFocus = i === act.focus

    const head = el('div', { class: 'ward-seg-head' }, [
      el('span', { class: 'ward-seq' }, [`seq ${e.seq}`]),
      sourceBadge(e.role),
      e.tool ? el('span', { class: 'ward-tool' }, [e.tool]) : null,
      seg.sig ? el('span', { class: 'ward-tool' }, ['signed']) : null,
    ])

    const body = el('p', { class: 'ward-body' }, [])
    for (const n of bodyNodes(e.body)) body.appendChild(n)

    const children: Node[] = [head, body]
    if (mode === 'lab' && seg_result) {
      children.push(fieldsTable(e, seg_result.leaf, seg_result.chain))
    }

    return el('li', { class: 'ward-seg', 'data-focus': String(isFocus) }, children)
  })

  return panel(
    'CONTEXT WINDOW',
    el('span', { class: 'ward-seq' }, [`${t.segments.length} segments`]),
    [el('ul', { class: 'ward-segments' }, items)],
  )
}

function verificationPanel(result: VerifyResult, agent: AgentRun): HTMLElement {
  const rows = checkRows(result)

  const verdict = !result.ok
    ? { kind: 'caught', icon: '✗', label: 'TAMPERING DETECTED', note: '' }
    : agent.compromised
      ? {
          kind: 'alarm',
          icon: '!',
          label: 'VERIFIED — AND COMPROMISED',
          note:
            'Every check below passed, and every one of them is telling the truth. The agent ' +
            'was compromised anyway. Authenticity is not safety.',
        }
      : { kind: 'clean', icon: '✓', label: 'VERIFIED', note: '' }

  const verdictNode = el(
    'div',
    { class: 'ward-verdict', 'data-verdict': verdict.kind, role: 'status', 'aria-live': 'polite' },
    [
      el('span', { class: 'ward-verdict-icon', 'aria-hidden': 'true' }, [verdict.icon]),
      el('span', {}, [
        el('span', { class: 'ward-verdict-label' }, [verdict.label]),
        verdict.note ? el('span', { class: 'ward-verdict-note' }, [verdict.note]) : null,
      ]),
    ],
  )

  const checkItems = rows.map((row) =>
    el('li', { class: 'ward-check', 'data-state': row.state === 'na' ? 'pending' : row.state }, [
      el('span', { class: 'ward-check-icon', 'aria-hidden': 'true' }, [
        row.state === 'ok' ? '✓' : row.state === 'fail' ? '✗' : '—',
      ]),
      el('span', {}, [
        el('span', { class: 'ward-check-name' }, [
          `${row.name} — ${row.state === 'ok' ? 'PASS' : row.state === 'fail' ? 'FAIL' : 'NOT CLAIMED'}`,
        ]),
        row.codes.length
          ? el('span', { class: 'ward-check-detail' }, [
              el('span', { class: 'ward-check-code' }, [
                row.codes.map((c) => `${c} (${failureName(c)})`).join(', '),
              ]),
            ])
          : null,
        el('span', { class: 'ward-check-detail' }, [row.detail]),
      ]),
    ]),
  )

  return panel('VERIFICATION', null, [
    verdictNode,
    el('ul', { class: 'ward-checks' }, checkItems),
    el('p', { class: 'ward-hash' }, [`head H_n = ${short(result.head)}…`]),
  ])
}

function agentPanel(agent: AgentRun, act: Act): HTMLElement {
  const steps = agent.steps.map((s) =>
    el('li', { class: 'ward-step', 'data-disposition': s.disposition }, [
      el('span', {}, [
        `seq ${s.seq} · ${ROLE_LABEL[s.role] ?? s.role} — ${
          s.disposition === 'obeyed' ? 'OBEYED' : 'read'
        }`,
      ]),
      s.action ? el('span', { class: 'ward-step-action' }, [s.action]) : null,
      el('span', { class: 'ward-step-note' }, [s.note]),
    ]),
  )

  return panel(
    'SCRIPTED AGENT',
    el('span', { class: 'ward-seq' }, [agent.compromised ? 'COMPROMISED' : 'nominal']),
    [
      el('p', { class: 'ward-note' }, [`Task: ${act.task}`]),
      el('ul', { class: 'ward-steps' }, steps),
      el('p', { class: 'ward-note', role: 'status', 'aria-live': 'polite' }, [agent.outcome]),
    ],
  )
}

// ---------------------------------------------------------------------------
// Act rendering
// ---------------------------------------------------------------------------

async function renderAct(container: HTMLElement, state: State): Promise<void> {
  const act = state.acts[state.actIndex] as Act
  const control = act.tampers.find((c) => c.id === state.activeTamper) ?? null

  const clean = await act.build()
  const transcript = control ? await control.apply(clean) : clean
  const result = await verifyTranscript(transcript)
  const agent = runAgent(transcript, act.task)

  clear(container)

  container.appendChild(
    el('div', { class: 'ward-act-head' }, [
      el('h2', { class: 'ward-act-title', id: 'act-title' }, [
        el('span', { class: 'ward-act-num' }, [`ACT ${act.label}`]),
        act.title,
      ]),
      el('p', { class: 'ward-act-question' }, [act.question]),
      el('p', { class: 'ward-act-intro' }, [act.intro]),
    ]),
  )

  if (act.cite) {
    container.appendChild(
      el('p', { class: 'ward-cite' }, [`${act.cite.id} — ${act.cite.why}`]),
    )
  }

  container.appendChild(
    el('div', { class: 'ward-grid' }, [
      transcriptPanel(transcript, result, act, state.mode),
      verificationPanel(result, agent),
      agentPanel(agent, act),
    ]),
  )

  if (act.tampers.length) {
    container.appendChild(tamperSection(act, control, result, state, container))
  }

  container.appendChild(
    el('div', { class: 'ward-lesson' }, [
      el('div', { class: 'ward-lesson-card', 'data-kind': 'does' }, [
        el('span', { class: 'ward-lesson-label' }, ['WHAT THIS ESTABLISHES']),
        el('p', {}, [act.establishes]),
      ]),
      el('div', { class: 'ward-lesson-card', 'data-kind': 'does-not' }, [
        el('span', { class: 'ward-lesson-label' }, ['WHAT IT DOES NOT']),
        el('p', {}, [act.doesNotEstablish]),
      ]),
    ]),
  )

  if (state.mode === 'lab') {
    container.appendChild(await rawSection(transcript))
  }
}

function tamperSection(
  act: Act,
  active: TamperControl | null,
  result: VerifyResult,
  state: State,
  container: HTMLElement,
): HTMLElement {
  const buttons: Node[] = [
    el('span', { class: 'ward-toolbar-label' }, ['BREAK IT:']),
    el(
      'button',
      { type: 'button', 'aria-pressed': String(state.activeTamper === null) },
      ['Untampered'],
    ),
  ]
  ;(buttons[1] as HTMLButtonElement).addEventListener('click', () => {
    state.activeTamper = null
    void renderAct(container, state)
  })

  for (const c of act.tampers) {
    const btn = el(
      'button',
      {
        type: 'button',
        class: c.expect === null ? 'ward-alarm-btn' : 'ward-danger',
        'aria-pressed': String(state.activeTamper === c.id),
      },
      [c.label],
    )
    btn.addEventListener('click', () => {
      state.activeTamper = c.id
      void renderAct(container, state)
    })
    buttons.push(btn)
  }

  const section = el('section', { class: 'ward-tampers', 'aria-label': 'Tamper controls' }, [
    el('div', { class: 'ward-toolbar' }, buttons),
  ])

  if (active) {
    const caught = !result.ok
    const codes = [...new Set(result.findings.map((f) => f.code))]
    section.appendChild(
      el(
        'div',
        {
          class: 'ward-tamper-result',
          'data-state': caught ? 'caught' : 'green',
          role: 'status',
          'aria-live': 'polite',
        },
        [
          el('p', {}, [
            el('span', { class: 'ward-tamper-code' }, [
              caught
                ? `CAUGHT — ${codes.map((c) => `${c} (${failureName(c)})`).join(', ')}`
                : 'NOT CAUGHT — every check still passes',
            ]),
          ]),
          el('p', {}, [active.lesson]),
        ],
      ),
    )
  }

  return section
}

async function rawSection(t: Transcript): Promise<HTMLElement> {
  const first = t.segments[0]
  const lines: string[] = []

  if (first) {
    const e = first.envelope
    lines.push('enc() breakdown for leaf_0 — the exact bytes that are hashed')
    lines.push('')
    const parts: [string, string][] = [
      ['enc("cw/v1/leaf")', toHex(enc('cw/v1/leaf'))],
      ['uint32be(v)', e.v.toString(16).padStart(8, '0')],
      ['enc(session)', `${toHex(enc(e.session)).slice(0, 24)}…`],
      ['uint32be(seq)', e.seq.toString(16).padStart(8, '0')],
      ['enc(role)', toHex(enc(e.role))],
      ['enc(tool ?? "")', toHex(enc(e.tool ?? ''))],
      ['enc(body)', `${toHex(enc(e.body)).slice(0, 24)}… (${enc(e.body).length - 4} bytes)`],
    ]
    for (const [label, hex] of parts) lines.push(`  ${label.padEnd(20)} ${hex}`)
    lines.push('')
    lines.push(`  SHA-256 of the above = ${await leafHashHex(e)}`)
    lines.push('')
    lines.push(
      'Note the uint32 length prefix on every string. That is what makes the encoding',
    )
    lines.push(
      'unambiguous: there is no syntax for two implementations to disagree about.',
    )
  }

  const raw = JSON.stringify(t, null, 2)

  return panel('FULL LAB — RAW SEALED TRANSCRIPT', null, [
    el(
      'div',
      { class: 'ward-scroll', tabindex: '0', role: 'group', 'aria-label': 'Encoding breakdown' },
      [el('pre', { class: 'ward-raw' }, [lines.join('\n')])],
    ),
    el('p', { class: 'ward-note' }, [
      'The full sealed transcript below is the exact JSON committed under /fixtures and read by ' +
        'verification/verify.py, which recomputes every value from the spec without importing ' +
        'any of this page’s code.',
    ]),
    el(
      'div',
      { class: 'ward-scroll', tabindex: '0', role: 'group', 'aria-label': 'Raw sealed transcript' },
      [el('pre', { class: 'ward-raw' }, [raw])],
    ),
  ])
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

export async function mount(root: HTMLElement): Promise<void> {
  const acts = await buildActs()
  const state: State = { acts, actIndex: 0, mode: 'demo', activeTamper: null }

  root.appendChild(hero())
  root.appendChild(disclosure())
  root.appendChild(threeQuestions())

  const actPanel = el('section', { 'aria-labelledby': 'act-title' })

  // Depth toggle.
  const modeButtons: HTMLButtonElement[] = []
  const modeBar = el('div', { class: 'ward-toolbar' }, [
    el('span', { class: 'ward-toolbar-label' }, ['DEPTH:']),
  ])
  for (const [mode, label] of [
    ['demo', 'Demo'],
    ['lab', 'Full lab'],
  ] as const) {
    const btn = el('button', { type: 'button', 'aria-pressed': String(state.mode === mode) }, [
      label,
    ])
    btn.addEventListener('click', () => {
      state.mode = mode
      for (const b of modeButtons) b.setAttribute('aria-pressed', String(b === btn))
      void renderAct(actPanel, state)
    })
    modeButtons.push(btn)
    modeBar.appendChild(btn)
  }
  root.appendChild(modeBar)

  // Act picker.
  const actButtons: HTMLButtonElement[] = []
  const actBar = el('div', { class: 'ward-toolbar' }, [
    el('span', { class: 'ward-toolbar-label' }, ['ACT:']),
  ])
  acts.forEach((a, i) => {
    const btn = el(
      'button',
      { type: 'button', 'aria-pressed': String(i === 0), 'aria-label': `Act ${a.label}: ${a.title}` },
      [a.label],
    )
    btn.addEventListener('click', () => {
      state.actIndex = i
      state.activeTamper = null
      for (const b of actButtons) b.setAttribute('aria-pressed', String(b === btn))
      void renderAct(actPanel, state)
    })
    actButtons.push(btn)
    actBar.appendChild(btn)
  })
  root.appendChild(actBar)
  root.appendChild(actPanel)

  await renderAct(actPanel, state)
}
