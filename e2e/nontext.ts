/**
 * Non-text contrast oracle (WCAG 1.4.11) for interactive controls.
 *
 * A control needs a visible boundary against its surroundings: either a painted
 * border or a fill that differs from the page behind it by at least 3:1.
 *
 * The per-side detection below is deliberate. The common implementation of this
 * oracle reads `borderTopStyle` alone while measuring all four border WIDTHS,
 * so a control bordered on one side only is mis-measured -- it looks bordered
 * because some width is non-zero, while the style it sampled belongs to a side
 * that is not painted. Each side is therefore resolved independently here:
 * a side counts as painted only when its own width, its own style AND its own
 * colour alpha all say so.
 */
import type { Page } from '@playwright/test'

export interface NonTextFinding {
  selector: string
  label: string
  reason: string
  ratio: number | null
  paintedSides: string[]
}

export async function auditControls(page: Page): Promise<NonTextFinding[]> {
  return page.evaluate(() => {
    function parse(c: string): [number, number, number, number] | null {
      const m = c.match(/rgba?\(([^)]+)\)/)
      if (!m || !m[1]) return null
      const p = m[1].split(/[,\s/]+/).filter(Boolean).map(Number)
      if (p.length < 3 || p.slice(0, 3).some(Number.isNaN)) return null
      return [p[0] as number, p[1] as number, p[2] as number, p.length > 3 ? (p[3] as number) : 1]
    }
    function lum(rgb: [number, number, number]): number {
      const f = (v: number) => {
        const s = v / 255
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)
      }
      return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2])
    }
    function over(fg: [number, number, number, number], bg: [number, number, number]): [number, number, number] {
      const a = fg[3]
      return [fg[0] * a + bg[0] * (1 - a), fg[1] * a + bg[1] * (1 - a), fg[2] * a + bg[2] * (1 - a)]
    }
    function ratioOf(a: [number, number, number], b: [number, number, number]): number {
      const l1 = lum(a)
      const l2 = lum(b)
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)
    }
    function effectiveBg(start: Element | null): [number, number, number] {
      const stack: [number, number, number, number][] = []
      let node = start
      while (node) {
        const bg = parse(getComputedStyle(node).backgroundColor)
        if (bg && bg[3] > 0) {
          stack.push(bg)
          if (bg[3] === 1) break
        }
        node = node.parentElement
      }
      let base: [number, number, number] = [0, 0, 0]
      const root = parse(getComputedStyle(document.documentElement).backgroundColor)
      if (root && root[3] === 1) base = [root[0], root[1], root[2]]
      for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i] as [number, number, number, number], base)
      return base
    }
    function selectorFor(el: Element): string {
      let s = el.tagName.toLowerCase()
      if (el.id) return `${s}#${el.id}`
      const cls = (el.getAttribute('class') || '').trim().split(/\s+/).filter(Boolean)[0]
      if (cls) s += `.${cls}`
      const label = (el.textContent || '').trim().slice(0, 24)
      return label ? `${s} "${label}"` : s
    }

    const SIDES = ['Top', 'Right', 'Bottom', 'Left'] as const
    const findings: NonTextFinding[] = []
    const controls = document.querySelectorAll('button, [role="button"], a[href], input, select, textarea')

    for (const el of Array.from(controls)) {
      const cs = getComputedStyle(el)
      if (cs.display === 'none' || cs.visibility === 'hidden') continue
      const rect = el.getBoundingClientRect()
      if (rect.width === 0 || rect.height === 0) continue

      // Each side resolved independently -- width AND style AND colour alpha.
      const painted: string[] = []
      for (const side of SIDES) {
        const w = parseFloat(cs.getPropertyValue(`border-${side.toLowerCase()}-width`))
        const style = cs.getPropertyValue(`border-${side.toLowerCase()}-style`)
        const col = parse(cs.getPropertyValue(`border-${side.toLowerCase()}-color`))
        if (w > 0 && style !== 'none' && style !== 'hidden' && col && col[3] > 0) {
          painted.push(side.toLowerCase())
        }
      }

      const outside = effectiveBg(el.parentElement)

      if (painted.length > 0) {
        // Judge the weakest painted side, not an arbitrary one.
        let worst = Infinity
        for (const side of painted) {
          const col = parse(cs.getPropertyValue(`border-${side}-color`))
          if (!col) continue
          worst = Math.min(worst, ratioOf(over(col, outside), outside))
        }
        if (worst + 0.005 < 3) {
          findings.push({
            selector: selectorFor(el),
            label: (el.textContent || '').trim().slice(0, 40),
            reason: 'painted border is below 3:1 against its surroundings',
            ratio: Math.round(worst * 100) / 100,
            paintedSides: painted,
          })
        }
        continue
      }

      // No painted border: the fill itself must carry the boundary.
      const own = parse(cs.backgroundColor)
      if (!own || own[3] === 0) {
        if (el.tagName === 'A') {
          // A link INSIDE prose must be distinguishable from the text around it,
          // so it needs an underline (WCAG 1.4.1). A standalone link -- a nav
          // item that is the only text in its container -- has nothing to be
          // confused with, and is judged by text contrast alone.
          if (cs.textDecorationLine.includes('underline')) continue
          // Strip the text of EVERY link in the parent, not just this one. What
          // remains is the prose a reader could confuse this link with. A nav
          // containing only links leaves nothing, so there is no confusion to
          // prevent and no underline required.
          const parent = el.parentElement
          if (parent) {
            let prose = parent.textContent || ''
            for (const a of Array.from(parent.querySelectorAll('a'))) {
              prose = prose.replace(a.textContent || '', '')
            }
            if (prose.trim() === '') continue
          }
        }
        findings.push({
          selector: selectorFor(el),
          label: (el.textContent || '').trim().slice(0, 40),
          reason: 'no painted border, no fill, and no underline',
          ratio: null,
          paintedSides: [],
        })
        continue
      }
      const r = ratioOf(over(own, outside), outside)
      if (r + 0.005 < 3) {
        findings.push({
          selector: selectorFor(el),
          label: (el.textContent || '').trim().slice(0, 40),
          reason: 'fill is below 3:1 against its surroundings and there is no painted border',
          ratio: Math.round(r * 100) / 100,
          paintedSides: [],
        })
      }
    }
    return findings
  })
}
