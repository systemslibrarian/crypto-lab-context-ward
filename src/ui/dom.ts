/**
 * Minimal DOM helpers.
 *
 * Everything is built with `createElement` and `textContent`. There is no
 * `innerHTML` anywhere in this exhibit: the content being rendered is
 * attacker-controlled by construction -- that is the entire subject -- and a
 * page about injection has no business interpreting it as markup.
 */

type Attrs = Record<string, string | boolean | undefined>
type Child = Node | string | null | undefined | false

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue
    if (v === true) node.setAttribute(k, '')
    else node.setAttribute(k, v)
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c)
  }
  return node
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild)
}

/** First 12 hex characters, the length used consistently for on-screen hashes. */
export function short(hex: string): string {
  return hex.slice(0, 12)
}
