/**
 * Shared gate machinery.
 *
 * The rules encoded here exist because the obvious way to write this file is
 * wrong in ways that make a gate report coverage it does not have:
 *
 *  - Motion is suppressed by EMULATING reduced-motion before navigation, not by
 *    injecting `*{animation:none!important}`. Injection bypasses the page's own
 *    `prefers-reduced-motion` block instead of exercising it, and where content
 *    is revealed by an animation's `forwards` fill it gets scanned invisible.
 *  - Nothing is force-revealed. `[hidden]` stays hidden and panels are reached
 *    by driving the real controls, so the scan sees states the page actually
 *    renders -- and the `[hidden]` cascade trap stays catchable.
 *  - Waits are on real content, never a fixed timeout.
 *  - `withTags()` and `withRules()` are run as SEPARATE analyses and merged.
 *    Chained, the second silently replaces the first via `options.runOnly`, and
 *    a gate can run four best-practice rules and zero WCAG rules while reading
 *    as a full A/AA pass.
 *  - axe's `incomplete` bucket is asserted, not just `violations`.
 */
import AxeBuilder from '@axe-core/playwright'
import { expect, type Page } from '@playwright/test'

export const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/** Rules worth running that are not carried by the WCAG tag sets. */
export const EXTRA_RULES = [
  'aria-allowed-role',
  'aria-dialog-name',
  'empty-table-header',
  'presentation-role-conflict',
]

/**
 * `incomplete` results accepted with a reason. Anything not listed fails.
 * An empty list is the goal; entries are evidence of a real limitation, not a
 * convenience.
 */
export const INCOMPLETE_BASELINE: { id: string; messageKey?: string; why: string }[] = [
  {
    id: 'color-contrast',
    messageKey: 'nonBmp',
    why:
      'axe declines to compute contrast for an element whose content is a single symbol glyph ' +
      '(the check ticks and crosses). Those glyphs are aria-hidden and every one of them sits ' +
      'beside the same outcome written as a word, so they are decorative. Their ratio is ' +
      'computed arithmetically by e2e/contrast.ts, which walks text nodes regardless of what ' +
      'axe was willing to judge, and they pass there at well above 4.5:1. This is the exact ' +
      'coverage gap the arithmetic oracle exists to fill.',
  },
]

export async function gotoWithReducedMotion(page: Page, path = ''): Promise<void> {
  // BEFORE navigation. Both `test.use({ reducedMotion })` and the
  // `reducedMotion` key in playwright.config.ts are measured no-ops on
  // Playwright 1.61.x, so this call is the one that actually takes effect.
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' })
  await page.goto(path)

  // Assert the emulation actually landed rather than trusting it.
  const reduced = await page.evaluate(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  )
  expect(reduced, 'reduced-motion emulation must be active in the page').toBe(true)
}

/**
 * Wait for the app to have rendered real content.
 *
 * The exhibit builds its DOM asynchronously (Ed25519 keygen is async), so a
 * scan that fired immediately would find an empty container and pass having
 * checked nothing.
 */
export async function waitForApp(page: Page): Promise<void> {
  await expect(page.locator('#app .ward-verdict')).toBeVisible()
  await expect(page.locator('#app .ward-check').first()).toBeVisible()
  await expect(page.locator('#app .ward-seg').first()).toBeVisible()
}

interface AxeResult {
  id: string
  help: string
  nodes: string[]
  messageKeys: string[]
}

export interface AxeOutcome {
  violations: AxeResult[]
  incomplete: AxeResult[]
}

/** Run the two rule sets as separate analyses and merge the results. */
export async function runAxe(page: Page): Promise<AxeOutcome> {
  const byTags = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze()
  const byRules = await new AxeBuilder({ page }).withRules(EXTRA_RULES).analyze()

  const shape = (rs: typeof byTags.violations): AxeResult[] =>
    rs.map((r) => ({
      id: r.id,
      help: r.help,
      nodes: r.nodes.map((n) => n.target.join(' ')).slice(0, 5),
      messageKeys: [
        ...new Set(
          r.nodes.flatMap((n) =>
            [...n.any, ...n.all, ...n.none]
              .map((c) => (c.data as { messageKey?: string } | null)?.messageKey)
              .filter((k): k is string => typeof k === 'string'),
          ),
        ),
      ],
    }))

  const dedupe = (rs: AxeResult[]) => {
    const seen = new Map<string, AxeResult>()
    for (const r of rs) if (!seen.has(r.id)) seen.set(r.id, r)
    return [...seen.values()]
  }

  return {
    violations: dedupe([...shape(byTags.violations), ...shape(byRules.violations)]),
    incomplete: dedupe([...shape(byTags.incomplete), ...shape(byRules.incomplete)]),
  }
}

export function assertAxeClean(outcome: AxeOutcome, where: string): void {
  expect(
    outcome.violations,
    `${where}: axe violations\n${JSON.stringify(outcome.violations, null, 2)}`,
  ).toEqual([])

  // Matched on messageKey as well as rule id, so baselining one narrow reason
  // cannot silently swallow a genuine finding from the same rule.
  const unexpected = outcome.incomplete.filter(
    (i) =>
      !INCOMPLETE_BASELINE.some(
        (b) =>
          b.id === i.id &&
          (b.messageKey === undefined ||
            (i.messageKeys.length > 0 && i.messageKeys.every((k) => k === b.messageKey))),
      ),
  )
  expect(
    unexpected,
    `${where}: axe INCOMPLETE results -- every contrast decision axe declined to ` +
      `make lands here, so these are not passes\n${JSON.stringify(unexpected, null, 2)}`,
  ).toEqual([])
}

/**
 * The `[hidden]` cascade probe.
 *
 * A class rule that sets `display` outranks the UA `[hidden]` rule, so an
 * element can paint while the code believes it is hidden. Nothing is
 * force-revealed anywhere in this suite precisely so this stays detectable.
 */
export async function assertHiddenReallyHidden(page: Page): Promise<void> {
  const leaks = await page.evaluate(() =>
    Array.from(document.querySelectorAll('[hidden]'))
      .filter((el) => getComputedStyle(el).display !== 'none')
      .map((el) => el.tagName.toLowerCase() + '.' + (el.getAttribute('class') || '')),
  )
  expect(leaks, '[hidden] elements that still paint').toEqual([])
}
