// Pure merge helpers (no Node imports) shared by the notes/report API routes.
// ---- Three-way merge (line based) ----------------------------------------
// Merges two edits of the same base text. Regions only one side changed are
// taken from that side; regions both sides changed identically are taken once;
// regions both changed differently become a conflict block with markers.
export const CONFLICT_START = '<<<<<<< your version'
export const CONFLICT_MID = '======='
export const CONFLICT_END = '>>>>>>> their version'

// LCS match of a against b: out[i] = index in b matched to a[i], or -1.
function lcsMatch(a: string[], b: string[]): number[] {
  const n = a.length, m = b.length
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1))
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) {
    dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
  }
  const out = new Array<number>(n).fill(-1)
  let i = 0, j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) { out[i] = j; i++; j++ } else if (dp[i + 1][j] >= dp[i][j + 1]) i++
    else j++
  }
  return out
}

const sameLines = (x: string[], y: string[]) => x.length === y.length && x.every((v, i) => v === y[i])

export function merge3(base: string, mine: string, theirs: string): { text: string; conflicts: number } {
  if (mine === theirs) return { text: mine, conflicts: 0 }
  if (base === theirs) return { text: mine, conflicts: 0 }
  if (base === mine) return { text: theirs, conflicts: 0 }
  const B = base.split('\n'), M = mine.split('\n'), T = theirs.split('\n')
  const bm = lcsMatch(B, M), bt = lcsMatch(B, T)
  const out: string[] = []
  let conflicts = 0
  let i = 0, m = 0, t = 0
  for (;;) {
    // Next base line kept by BOTH sides is a stable anchor.
    let k = i
    while (k < B.length && (bm[k] < 0 || bt[k] < 0)) k++
    const mEnd = k < B.length ? bm[k] : M.length
    const tEnd = k < B.length ? bt[k] : T.length
    const rb = B.slice(i, k), rm = M.slice(m, mEnd), rt = T.slice(t, tEnd)
    if (sameLines(rm, rb)) out.push(...rt)
    else if (sameLines(rt, rb) || sameLines(rm, rt)) out.push(...rm)
    else { conflicts++; out.push(CONFLICT_START, ...rm, CONFLICT_MID, ...rt, CONFLICT_END) }
    if (k >= B.length) break
    out.push(B[k])
    i = k + 1; m = mEnd + 1; t = tEnd + 1
  }
  return { text: out.join('\n'), conflicts }
}

