/**
 * Path-list → nested tree.
 *
 * The list endpoint returns flat, fully-qualified paths:
 *
 *   ["myapp/db/password", "myapp/db/user", "myapp/api-key", "other/thing"]
 *
 * which the UI renders as an expandable hierarchy. Note that a path can be
 * *both* a folder and a secret ("a" and "a/b" may both exist), so `isLeaf` and
 * `children.length > 0` are independent — a node can be both.
 *
 * Kept out of the component file so it can be unit-tested without a renderer.
 */

export interface TreeNode {
  /** Last path segment — what the row displays. */
  name: string
  /** Fully-qualified path from the root. Stable React key. */
  path: string
  /** True when a secret exists at exactly this path (vs. an implied folder). */
  isLeaf: boolean
  children: TreeNode[]
}

interface MutableNode extends TreeNode {
  children: MutableNode[]
  childIndex: Map<string, MutableNode>
}

function makeNode(name: string, path: string): MutableNode {
  return { name, path, isLeaf: false, children: [], childIndex: new Map() }
}

/**
 * Build a sorted tree from flat paths in O(total segments).
 *
 * The previous implementation ran `paths.some(...)` inside `paths.map(...)` —
 * O(n²) on every render — and then rendered the result flat, so expanding a
 * folder did nothing. This walks each path once through a segment index.
 */
export function buildSecretTree(paths: readonly string[]): TreeNode[] {
  const root = makeNode('', '')

  for (const raw of paths) {
    const segments = raw.split('/').filter(Boolean)
    if (segments.length === 0) continue

    let cursor = root
    let prefix = ''

    for (const segment of segments) {
      prefix = prefix ? `${prefix}/${segment}` : segment
      let next = cursor.childIndex.get(segment)
      if (!next) {
        next = makeNode(segment, prefix)
        cursor.childIndex.set(segment, next)
        cursor.children.push(next)
      }
      cursor = next
    }

    // Only the terminal segment of a listed path is a real secret.
    cursor.isLeaf = true
  }

  return sortAndStrip(root.children)
}

/**
 * Sort folders before leaves, then alphabetically, and drop the internal index.
 * A node that is both a folder and a secret sorts with the folders.
 */
function sortAndStrip(nodes: MutableNode[]): TreeNode[] {
  return nodes
    .sort((a, b) => {
      const aIsFolder = a.children.length > 0
      const bIsFolder = b.children.length > 0
      if (aIsFolder !== bIsFolder) return aIsFolder ? -1 : 1
      return a.name.localeCompare(b.name)
    })
    .map(node => ({
      name: node.name,
      path: node.path,
      isLeaf: node.isLeaf,
      children: sortAndStrip(node.children),
    }))
}

/** Every ancestor path of `path`, nearest-first. `a/b/c` → ["a/b", "a"]. */
export function ancestorsOf(path: string): string[] {
  const segments = path.split('/').filter(Boolean)
  const out: string[] = []
  for (let i = segments.length - 1; i > 0; i--) {
    out.push(segments.slice(0, i).join('/'))
  }
  return out
}
