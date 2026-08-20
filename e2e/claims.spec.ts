/**
 * The claims suite: does the page tell the truth?
 *
 * Two disciplines are mixed deliberately.
 *
 *   CROSS-CHECKS -- two surfaces that must agree (the segment counter versus
 *   the rows it counts; the verdict versus the check rows beneath it; the
 *   rendered disclosure versus the exported constant).
 *
 *   INDEPENDENT RE-DERIVATIONS -- recompute the claim from the page's own raw
 *   inputs by a DIFFERENT route than the source takes. The chain re-derivation
 *   below reimplements enc/leaf/chain against `node:crypto`, so it is a third
 *   implementation, not a second call into the first. A test that re-derives a
 *   value the same way the source does will happily agree with a bug.
 *
 * Plus a browser-versus-Python cross-check: the failure codes the page prints
 * are compared against `fixtures/MANIFEST.json`, whose expectations
 * `verification/verify.py` independently confirms.
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { expect, test, type Page } from '@playwright/test'
import { gotoWithReducedMotion, waitForApp } from './gate.ts'
import { SCRIPTED_TRANSCRIPT_DISCLOSURE } from '../src/agent-mock.ts'

// --- A third implementation of the leaf/chain arithmetic --------------------

function enc(s: string): Buffer {
  const body = Buffer.from(s, 'utf8')
  const len = Buffer.alloc(4)
  len.writeUInt32BE(body.length, 0)
  return Buffer.concat([len, body])
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32BE(n, 0)
  return b
}

interface RawEnvelope {
  v: number
  session: string
  seq: number
  role: string
  tool: string | null
  body: string
  prev: string
}

function leafOf(e: RawEnvelope): Buffer {
  return createHash('sha256')
    .update(
      Buffer.concat([
        enc('cw/v1/leaf'),
        u32(e.v),
        enc(e.session),
        u32(e.seq),
        enc(e.role),
        enc(e.tool ?? ''),
        enc(e.body),
      ]),
    )
    .digest()
}

function headOf(segments: { envelope: RawEnvelope }[]): string {
  let h = Buffer.alloc(32)
  for (const s of segments) {
    h = createHash('sha256')
      .update(Buffer.concat([enc('cw/v1/chain'), h, leafOf(s.envelope)]))
      .digest()
  }
  return h.toString('hex')
}

// --- Manifest, as verified by verify.py ------------------------------------

interface ManifestEntry {
  file: string
  expect: string
  expect_codes: string[]
  agent_compromised?: boolean
  note: string
}

const manifest = JSON.parse(readFileSync('fixtures/MANIFEST.json', 'utf8')) as {
  entries: ManifestEntry[]
}

/** "Act 7 tamper control "Drop a segment" -- advertised failure: SEQ_GAP." */
function tamperEntry(actLabel: string, buttonLabel: string): ManifestEntry | undefined {
  return manifest.entries.find((e) => {
    const m = e.note.match(/^Act (\S+) tamper control "(.+)" -- advertised failure/)
    return m && m[1] === actLabel && m[2] === buttonLabel
  })
}

async function rawTranscript(page: Page): Promise<{ segments: { envelope: RawEnvelope }[] }> {
  await page.getByRole('button', { name: 'Full lab' }).click()
  const blocks = page.locator('#app .ward-raw')
  await expect(blocks.last()).toBeVisible()
  const text = (await blocks.last().textContent()) ?? ''
  return JSON.parse(text) as { segments: { envelope: RawEnvelope }[] }
}

async function selectAct(page: Page, label: string): Promise<void> {
  await page.locator(`#app button[aria-label^="Act ${label}:"]`).click()
  await expect(page.locator('#app .ward-act-num')).toHaveText(`ACT ${label}`)
}

// ---------------------------------------------------------------------------

test.describe('the page tells the truth', () => {
  test('the printed chain head re-derives from the page’s own raw transcript', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    for (const label of ['1', '2', '8a']) {
      await selectAct(page, label)
      const t = await rawTranscript(page)

      const printed = ((await page.locator('#app .ward-hash').textContent()) ?? '').trim()
      const m = printed.match(/head H_n = ([0-9a-f]+)/)
      expect(m, `act ${label}: the head hash should be printed`).toBeTruthy()

      // Recomputed here from the raw envelopes, via node:crypto, not by
      // calling anything the page uses.
      const recomputed = headOf(t.segments)
      expect(recomputed.startsWith(m![1] as string), `act ${label}: head mismatch`).toBe(true)
    }
  })

  test('the segment counter agrees with the rows it counts', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    for (const label of ['1', '3', '7']) {
      await selectAct(page, label)
      const counter = ((await page.locator('#app .ward-panel-head .ward-seq').first().textContent()) ?? '').trim()
      const claimed = Number(counter.split(' ')[0])
      const rendered = await page.locator('#app .ward-seg').count()
      expect(claimed, `act ${label}: counter says ${counter}`).toBe(rendered)

      const raw = await rawTranscript(page)
      expect(raw.segments.length, `act ${label}: raw transcript length`).toBe(rendered)
    }
  })

  test('the verdict agrees with the check rows beneath it', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    const labels = ['1', '2', '3', '4', '5', '6', '7', '8a', '8b']
    for (const label of labels) {
      await selectAct(page, label)
      const rows = await page.locator('#app .ward-check-name').allTextContents()
      const anyFail = rows.some((r) => r.endsWith('FAIL'))
      const verdict = ((await page.locator('#app .ward-verdict-label').textContent()) ?? '').trim()
      const agentState = ((await page.locator('#app .ward-panel-head .ward-seq').nth(1).textContent()) ?? '').trim()

      if (anyFail) {
        expect(verdict, `act ${label}`).toBe('TAMPERING DETECTED')
      } else if (agentState === 'COMPROMISED') {
        expect(verdict, `act ${label}`).toBe('VERIFIED — AND COMPROMISED')
      } else {
        expect(verdict, `act ${label}`).toBe('VERIFIED')
      }
    }
  })

  test('NEG-1 on screen: acts 2, 3, 4, 8a and 8b are fully green AND compromised', async ({
    page,
  }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    for (const label of ['2', '3', '4', '8a', '8b']) {
      await selectAct(page, label)

      const rows = await page.locator('#app .ward-check-name').allTextContents()
      expect(rows.length).toBeGreaterThan(0)
      for (const r of rows) {
        expect(r, `act ${label}: no check may fail`).not.toMatch(/FAIL$/)
      }

      await expect(
        page.locator('#app .ward-verdict'),
        `act ${label}: the verdict must read as an alarm, not a green success`,
      ).toHaveAttribute('data-verdict', 'alarm')

      // The agent obeyed at least one attacker directive.
      expect(await page.locator('#app .ward-step[data-disposition="obeyed"]').count()).toBeGreaterThan(0)

      // And the manifest, which verify.py confirms, agrees this fixture is clean.
      const entry = manifest.entries.find((e) => e.file === `transcripts/act${label}.json`)
      expect(entry?.expect, `act ${label} manifest`).toBe('ok')
      expect(entry?.agent_compromised, `act ${label} manifest`).toBe(true)
    }
  })

  test('act 1 is the control: green and NOT compromised', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)
    await selectAct(page, '1')

    await expect(page.locator('#app .ward-verdict')).toHaveAttribute('data-verdict', 'clean')
    expect(await page.locator('#app .ward-step[data-disposition="obeyed"]').count()).toBe(0)

    const entry = manifest.entries.find((e) => e.file === 'transcripts/act1.json')
    expect(entry?.agent_compromised).toBe(false)
  })

  test('every failure path names its actual cause, and matches the Python-verified manifest', async ({
    page,
  }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    let checked = 0
    for (const label of ['2', '3', '6', '7', '8a']) {
      await selectAct(page, label)
      const buttons = page.locator('#app .ward-tampers button')
      const n = await buttons.count()

      for (let i = 1; i < n; i++) {
        const buttonLabel = ((await buttons.nth(i).textContent()) ?? '').trim()
        await buttons.nth(i).click()

        const result = page.locator('#app .ward-tamper-result')
        await expect(result).toBeVisible()
        const printed = ((await result.locator('.ward-tamper-code').textContent()) ?? '').trim()

        const entry = tamperEntry(label, buttonLabel)
        expect(entry, `no manifest entry for act ${label} / "${buttonLabel}"`).toBeTruthy()

        if (entry!.expect === 'ok') {
          // The compromised-host control: advertised as producing no failure.
          expect(printed, `act ${label} / ${buttonLabel}`).toContain('NOT CAUGHT')
          await expect(result).toHaveAttribute('data-state', 'green')
        } else {
          expect(printed, `act ${label} / ${buttonLabel}`).toContain('CAUGHT')
          await expect(result).toHaveAttribute('data-state', 'caught')
          for (const code of entry!.expect_codes) {
            expect(printed, `act ${label} / ${buttonLabel} must name ${code}`).toContain(code)
          }
          // The failing check row must be the one that owns the code, not just
          // any row -- two surfaces that have to agree.
          const failing = await page.locator('#app .ward-check[data-state="fail"] .ward-check-code').allTextContents()
          for (const code of entry!.expect_codes) {
            expect(failing.join(' '), `act ${label}: check rows must name ${code}`).toContain(code)
          }
        }
        checked++
      }
    }
    expect(checked, 'every tamper control across the sampled acts was exercised').toBeGreaterThanOrEqual(11)
  })

  test('the scripted-transcript disclosure is printed verbatim and persistently', async ({
    page,
  }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    const disclosure = page.locator('.ward-disclosure p')
    await expect(disclosure).toHaveText(SCRIPTED_TRANSCRIPT_DISCLOSURE)

    // Persistent, not a footnote: still present after changing act, depth and
    // tamper state.
    await selectAct(page, '8b')
    await page.getByRole('button', { name: 'Full lab' }).click()
    await expect(disclosure).toBeVisible()
    await expect(disclosure).toHaveText(SCRIPTED_TRANSCRIPT_DISCLOSURE)

    // And there is no API-key field anywhere, because there is no model.
    expect(await page.locator('input[type="password"], input[name*="key" i]').count()).toBe(0)
  })

  test('the three questions state plainly that one of them is unanswered', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    const unanswered = page.locator('.ward-question[data-answered="no"]')
    await expect(unanswered).toHaveCount(1)
    await expect(unanswered).toContainText('Should the model obey it?')
    await expect(unanswered).toContainText('NOT ANSWERED')
    await expect(page.locator('.ward-question[data-answered="yes"]')).toHaveCount(2)
  })

  test('switching act retires the tamper state rather than leaving it stale', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    await selectAct(page, '7')
    await page.getByRole('button', { name: 'Drop a segment' }).click()
    await expect(page.locator('#app .ward-tamper-result')).toBeVisible()
    await expect(page.locator('#app .ward-verdict')).toHaveAttribute('data-verdict', 'caught')

    await selectAct(page, '1')
    // The stale verdict is gone, and the control has visibly returned to
    // "Untampered" rather than silently keeping a pressed button.
    await expect(page.locator('#app .ward-tamper-result')).toHaveCount(0)
    await expect(page.locator('#app .ward-verdict')).toHaveAttribute('data-verdict', 'clean')
    await expect(page.getByRole('button', { name: 'Untampered' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
  })

  test('no-op guard: re-selecting the same act does not retire a fresh verdict', async ({
    page,
  }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    await selectAct(page, '6')
    await page.getByRole('button', { name: 'COMPROMISED HOST' }).click()
    const before = await page.locator('#app .ward-tamper-result').textContent()
    await expect(page.locator('#app .ward-verdict')).toHaveAttribute('data-verdict', 'alarm')

    // Re-press the depth control it is already on; the tamper state must survive.
    await page.getByRole('button', { name: 'Demo' }).click()
    await expect(page.locator('#app .ward-tamper-result')).toHaveText(before ?? '')
    await expect(page.locator('#app .ward-verdict')).toHaveAttribute('data-verdict', 'alarm')
  })

  test('[hidden] elements really are hidden', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)
    const leaks = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[hidden]')).filter(
        (el) => getComputedStyle(el).display !== 'none',
      ).length,
    )
    expect(leaks).toBe(0)
  })

  test('no network request leaves the page', async ({ page }) => {
    const external: string[] = []
    page.on('request', (r) => {
      const url = r.url()
      if (!url.startsWith('http://localhost:4671/')) external.push(url)
    })

    await gotoWithReducedMotion(page)
    await waitForApp(page)
    await selectAct(page, '8a')
    await page.getByRole('button', { name: 'Full lab' }).click()
    await expect(page.locator('#app .ward-raw').first()).toBeVisible()

    expect(external, `unexpected outbound requests: ${external.join(', ')}`).toEqual([])
  })
})
