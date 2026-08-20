/**
 * Arithmetic text-contrast oracle (WCAG 1.4.3).
 *
 * This runs ALONGSIDE axe rather than instead of it. axe pushes any contrast
 * decision it declines to make into its `incomplete` bucket -- it refuses to
 * compute contrast over a gradient or an unresolved `color-mix()` -- and a gate
 * that only reads `violations` scores those as passes. Computing the ratio here
 * means a colour axe gave up on is still judged.
 */
import type { Page } from '@playwright/test'

export interface ContrastFinding {
  selector: string
  text: string
  color: string
  background: string
  ratio: number
  required: number
  fontPx: number
  bold: boolean
}

export async function auditTextContrast(page: Page): Promise<ContrastFinding[]> {
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

    /** Composite every ancestor background down to an opaque colour. */
    function effectiveBg(el: Element): [number, number, number] {
      const stack: [number, number, number, number][] = []
      let node: Element | null = el
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
      const parts: string[] = []
      let node: Element | null = el
      for (let i = 0; node && i < 4; i++) {
        let s = node.tagName.toLowerCase()
        if (node.id) {
          s += `#${node.id}`
          parts.unshift(s)
          break
        }
        const cls = (node.getAttribute('class') || '').trim().split(/\s+/).filter(Boolean)[0]
        if (cls) s += `.${cls}`
        parts.unshift(s)
        node = node.parentElement
      }
      return parts.join(' > ')
    }

    const findings: ContrastFinding[] = []
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    const seen = new Set<Element>()

    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = (n.textContent || '').trim()
      if (!text) continue
      const el = n.parentElement
      if (!el || seen.has(el)) continue
      seen.add(el)

      const cs = getComputedStyle(el)
      if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) === 0) continue
      const rect = el.getBoundingClientRect()
      if (rect.width === 0 || rect.height === 0) continue

      const fg = parse(cs.color)
      if (!fg) continue
      const bg = effectiveBg(el)
      const fgOpaque = over(fg, bg)

      const l1 = lum(fgOpaque)
      const l2 = lum(bg)
      const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)

      const fontPx = parseFloat(cs.fontSize)
      const weight = Number(cs.fontWeight) || (cs.fontWeight === 'bold' ? 700 : 400)
      const bold = weight >= 700
      const large = fontPx >= 24 || (bold && fontPx >= 18.66)
      const required = large ? 3 : 4.5

      if (ratio + 0.005 < required) {
        findings.push({
          selector: selectorFor(el),
          text: text.slice(0, 60),
          color: cs.color,
          background: `rgb(${bg.map((v) => Math.round(v)).join(', ')})`,
          ratio: Math.round(ratio * 100) / 100,
          required,
          fontPx,
          bold,
        })
      }
    }
    return findings
  })
}
