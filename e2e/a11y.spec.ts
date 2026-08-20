/**
 * WCAG 2.1 A/AA gate.
 *
 * Scans the production build, in the states the page actually renders, reached
 * by driving the real controls. See `e2e/gate.ts` for why each rule is written
 * the way it is.
 */
import { expect, test } from '@playwright/test'
import {
  assertAxeClean,
  assertHiddenReallyHidden,
  gotoWithReducedMotion,
  runAxe,
  waitForApp,
} from './gate.ts'
import { auditTextContrast } from './contrast.ts'
import { auditControls } from './nontext.ts'
import { NONTEXT_BASELINE } from './nontext-baseline.ts'

test.describe('accessibility', () => {
  test('shipped default state is clean', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    // Assert the shipped defaults BEFORE scanning, so an empty or half-built
    // render cannot pass by having nothing to find.
    await expect(page.locator('h1')).toHaveText('Context Ward')
    await expect(page.locator('#app .ward-act-num')).toHaveText('ACT 1')
    await expect(page.locator('#app button[aria-pressed="true"]').first()).toHaveText('Demo')

    assertAxeClean(await runAxe(page), 'default state')
    await assertHiddenReallyHidden(page)
  })

  test('exactly one h1 and one banner landmark', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)
    await expect(page.locator('h1')).toHaveCount(1)
    // The top bar is the banner; the hero is page content.
    await expect(page.locator('body > header, [role="banner"]')).toHaveCount(1)
    await expect(page.locator('main#app')).toHaveCount(1)
  })

  test('every act is clean, reached through the real controls', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    const actButtons = page.locator('#app .ward-toolbar').nth(1).locator('button')
    const count = await actButtons.count()
    expect(count).toBe(9)

    for (let i = 0; i < count; i++) {
      const label = await actButtons.nth(i).textContent()
      await actButtons.nth(i).click()
      await expect(page.locator('#app .ward-act-num')).toHaveText(`ACT ${label}`)
      await expect(page.locator('#app .ward-verdict')).toBeVisible()
      assertAxeClean(await runAxe(page), `act ${label}`)
    }
  })

  test('full lab depth is clean, including the scrollable regions', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    await page.getByRole('button', { name: 'Full lab' }).click()
    await expect(page.locator('#app .ward-raw').first()).toBeVisible()

    // Scrollable regions need a name and keyboard reach on the Linux runner.
    const scrollers = page.locator('#app .ward-scroll')
    const n = await scrollers.count()
    expect(n).toBeGreaterThan(0)
    for (let i = 0; i < n; i++) {
      await expect(scrollers.nth(i)).toHaveAttribute('tabindex', '0')
      const name = await scrollers.nth(i).getAttribute('aria-label')
      expect(name, 'every scrollable region needs an accessible name').toBeTruthy()
    }

    assertAxeClean(await runAxe(page), 'full lab')
  })

  test('every tamper state is clean', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    // Act 6 carries the widest set, including the compromised-host control.
    await page.getByRole('button', { name: 'Act 6:' }).click()
    await expect(page.locator('#app .ward-act-num')).toHaveText('ACT 6')

    const tampers = page.locator('#app .ward-tampers button')
    const n = await tampers.count()
    expect(n).toBeGreaterThan(1)
    for (let i = 0; i < n; i++) {
      await tampers.nth(i).click()
      await expect(page.locator('#app .ward-verdict')).toBeVisible()
      assertAxeClean(await runAxe(page), `act 6 tamper ${i}`)
    }
  })

  test('text contrast computed arithmetically, not only by axe', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)
    await page.getByRole('button', { name: 'Full lab' }).click()
    await expect(page.locator('#app .ward-raw').first()).toBeVisible()

    const findings = await auditTextContrast(page)
    expect(findings, `text below its required ratio:\n${JSON.stringify(findings, null, 2)}`).toEqual([])
  })

  test('interactive controls have a visible boundary', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    const findings = (await auditControls(page)).filter(
      (f) => !NONTEXT_BASELINE.some((b) => b.selector === f.selector),
    )
    expect(findings, `controls below 3:1:\n${JSON.stringify(findings, null, 2)}`).toEqual([])
  })

  test('state is never conveyed by colour alone', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    // Every check row carries a word (PASS / FAIL / NOT CLAIMED) beside its
    // colour and icon, and the icon is aria-hidden so it is never the only
    // thing a screen reader gets.
    const names = await page.locator('#app .ward-check-name').allTextContents()
    expect(names.length).toBeGreaterThan(0)
    for (const n of names) {
      expect(n, `check row must state its outcome in words: ${n}`).toMatch(
        /(PASS|FAIL|NOT CLAIMED)$/,
      )
    }
    for (const icon of await page.locator('#app .ward-check-icon').all()) {
      await expect(icon).toHaveAttribute('aria-hidden', 'true')
    }
    await expect(page.locator('#app .ward-verdict-label')).toHaveText(/VERIFIED|TAMPERING/)
  })

  test('layout stacks below 640px with no horizontal overflow', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    )
    expect(overflow, 'the page body must not scroll horizontally').toBeLessThanOrEqual(1)

    assertAxeClean(await runAxe(page), 'narrow viewport')
  })

  test('keyboard reaches the controls with a visible focus ring', async ({ page }) => {
    await gotoWithReducedMotion(page)
    await waitForApp(page)

    await page.keyboard.press('Tab')
    const skip = await page.evaluate(() => document.activeElement?.className ?? '')
    expect(skip, 'the first tab stop should be the skip link').toContain('cl-skip')

    // Walk into the app and confirm the focused control paints an outline.
    for (let i = 0; i < 12; i++) await page.keyboard.press('Tab')
    const outline = await page.evaluate(() => {
      const el = document.activeElement
      if (!el) return null
      const cs = getComputedStyle(el)
      return { tag: el.tagName, width: cs.outlineWidth, style: cs.outlineStyle }
    })
    expect(outline).not.toBeNull()
    expect(outline!.style).not.toBe('none')
    expect(parseFloat(outline!.width)).toBeGreaterThan(0)
  })
})
