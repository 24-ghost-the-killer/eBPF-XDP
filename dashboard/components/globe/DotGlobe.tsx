"use client"
// DotGlobe -- vendored source of the Framer component "AisolDotGlobe"
// (https://framer.com/m/AisolDotGlobe-H7p0ip.js@38lF6UHMFqRbthU4EBlv, build R10-2 v1.1),
// recovered from its published source map on 2026-11-14. Kept as local source so
// the dashboard never loads code from a URL at runtime.
//
// Local changes (rendering code is untouched):
//   * removed the `framer` runtime: no useIsStaticRenderer (always the live
//     globe; the flat SVG still paints first and is the no-WebGL fallback) and
//     no addPropertyControls / Framer metadata;
//   * exported a typed props interface whose groups accept partial values.
// Interaction added for the attack-origins view (xdp-sentinel):
//   * labels never overlap: each frame they are placed by priority, tried on
//     both sides of their marker and hidden when there is no free room;
//   * click / tap a marker, its label or its arc to select it (onSelect); the
//     globe turns and zooms so the whole link is in view, other links dim;
//   * zoom: pinch (touch or trackpad), Ctrl/Cmd + scroll, +/- keys, apiRef;
//   * per-pin `weight` (0..1) sets the arc's thickness.
// Depends only on react + three (pinned in package.json).
// build: R10-2 v1.1 (Dot Globe — three core only, land dots baked from Natural Earth, orthographic camera)
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import type { CSSProperties, ReactNode } from "react"
import * as THREE from "three"

// Framer bundles whichever three.js the project already resolved, so this code can meet an old release.
// r154 renamed the output shader chunk and r152 introduced colour management; older releases pass the
// sRGB colours straight through, which gives the same picture.
const THREE_REV = parseInt(String((THREE as { REVISION?: string }).REVISION || "0"), 10) || 0
const CS_CHUNK = THREE_REV >= 154 ? "#include <colorspace_fragment>" : THREE_REV >= 152 ? "#include <encodings_fragment>" : ""

/**
 * DotGlobe
 * A dotted 3D globe for hero and "we work worldwide" sections. Land is drawn
 * as dots sampled from Natural Earth coastlines that ship inside this file,
 * so nothing is downloaded. Your cities appear as glowing pins with labels,
 * joined by travelling arcs. Visitors can grab the globe and fling it; at
 * rest it turns slowly. Only nodes inside this component are read or written.
 *
 * @framerIntrinsicWidth 600
 * @framerIntrinsicHeight 600
 * @framerSupportedLayoutWidth any-prefer-fixed
 * @framerSupportedLayoutHeight any-prefer-fixed
 */

type ColorValue = string | { value?: string }
export type ArcMode = "off" | "chain" | "hub"

export interface Pin {
    label?: string
    lat?: number
    lng?: number
    /** 0..1: the arc to this pin is drawn thicker the larger this is. */
    weight?: number
}

/** Imperative controls (zoom buttons etc.), handed out through `apiRef`. */
export interface DotGlobeApi {
    zoomBy(factor: number): void
    reset(): void
}

interface Markers {
    color: ColorValue
    size: number
    labels: boolean
    labelColor: ColorValue
    pulse: boolean
}

interface GlobeLook {
    size: number
    dotColor: ColorValue
    dotSize: number
    density: number
    oceanColor: ColorValue
    oceanOpacity: number
    glowColor: ColorValue
    glow: number
}

interface Arcs {
    mode: ArcMode
    color: ColorValue
    speed: number
}

interface Motion {
    autoRotate: boolean
    speed: number
    drag: boolean
    startLng: number
    tilt: number
}

interface Background {
    transparent: boolean
    color: ColorValue
}

interface Props {
    pins: Pin[]
    markers: Markers
    globe: GlobeLook
    arcs: Arcs
    motion: Motion
    background: Background
    label: string
    style?: CSSProperties
}

const DEFAULT_PINS: Pin[] = [
    { label: "London", lat: 51.51, lng: -0.13 },
    { label: "New York", lat: 40.71, lng: -74.01 },
    { label: "São Paulo", lat: -23.55, lng: -46.63 },
    { label: "Nairobi", lat: -1.29, lng: 36.82 },
    { label: "Singapore", lat: 1.35, lng: 103.82 },
    { label: "Tokyo", lat: 35.68, lng: 139.69 },
]
const DEFAULT_MARKERS: Markers = { color: "#FFB35C", size: 100, labels: true, labelColor: "#E8ECF7", pulse: true }
const DEFAULT_GLOBE: GlobeLook = {
    size: 78,
    dotColor: "#8FA3FF",
    dotSize: 60,
    density: 55,
    oceanColor: "#0E1428",
    oceanOpacity: 85,
    glowColor: "#4F6BFF",
    glow: 60,
}
const DEFAULT_ARCS: Arcs = { mode: "hub", color: "#FFB35C", speed: 50 }
const DEFAULT_MOTION: Motion = { autoRotate: true, speed: 6, drag: true, startLng: 10, tilt: 22 }
const DEFAULT_BACKGROUND: Background = { transparent: false, color: "#070A12" }
const DEFAULT_LABEL = ""

const tok = (v?: ColorValue): string => (!v ? "" : typeof v === "string" ? v : v.value || "")
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))
const num = (v: unknown, fallback: number) => (typeof v === "number" && Number.isFinite(v) ? v : fallback)

// Colours for CSS keep the author's string (tokens included); WebGL needs a concrete colour.
function cssColor(v: ColorValue | undefined, fallback: string): string {
    return tok(v) || fallback
}
function glColor(v: ColorValue | undefined, fallback: string): string {
    let s = tok(v).trim()
    const m = /^var\([^,]+,\s*(.+)\)$/.exec(s)
    if (m) s = m[1].trim()
    if (!s) return fallback
    if (/^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i.test(s)) return s.length === 9 ? s.slice(0, 7) : s
    const rgb = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(s)
    if (rgb) return `rgb(${Math.round(+rgb[1])}, ${Math.round(+rgb[2])}, ${Math.round(+rgb[3])})`
    const hsl = /^hsla?\(\s*([\d.]+)(?:deg)?[\s,]+([\d.]+)%[\s,]+([\d.]+)%/i.exec(s)
    if (hsl) return `hsl(${+hsl[1]}, ${+hsl[2]}%, ${+hsl[3]}%)`
    return fallback
}

// Labels get a halo in the opposite tone so they read on any ocean or background.
function isDarkInk(c: string): boolean {
    let r = 255
    let g = 255
    let b = 255
    const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(c)
    const rgb = /^rgb\((\d+), (\d+), (\d+)\)$/.exec(c)
    const hsl = /^hsl\(([\d.]+), ([\d.]+)%, ([\d.]+)%\)$/.exec(c)
    if (hex) {
        const h = hex[1].length === 3 ? hex[1].replace(/./g, (x) => x + x) : hex[1]
        r = parseInt(h.slice(0, 2), 16)
        g = parseInt(h.slice(2, 4), 16)
        b = parseInt(h.slice(4, 6), 16)
    } else if (rgb) {
        r = +rgb[1]
        g = +rgb[2]
        b = +rgb[3]
    } else if (hsl) return +hsl[3] < 50
    return 0.2126 * r + 0.7152 * g + 0.0722 * b < 128
}

function merge(props: Partial<Props>): Props {
    const pins = Array.isArray(props.pins) && props.pins.length ? props.pins : DEFAULT_PINS
    return {
        pins,
        markers: { ...DEFAULT_MARKERS, ...(props.markers || {}) },
        globe: { ...DEFAULT_GLOBE, ...(props.globe || {}) },
        arcs: { ...DEFAULT_ARCS, ...(props.arcs || {}) },
        motion: { ...DEFAULT_MOTION, ...(props.motion || {}) },
        background: { ...DEFAULT_BACKGROUND, ...(props.background || {}) },
        label: typeof props.label === "string" ? props.label : DEFAULT_LABEL,
        style: props.style,
    }
}

interface CleanPin {
    label: string
    lat: number
    lng: number
    weight: number
}

function cleanPins(pins: Pin[]): CleanPin[] {
    const out: CleanPin[] = []
    for (const p of pins) {
        if (!p) continue
        const lat = num(p.lat, NaN)
        const lng = num(p.lng, NaN)
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) continue
        out.push({ label: (p.label || "").trim(), lat: clamp(lat, -90, 90), lng: ((((lng + 180) % 360) + 360) % 360) - 180, weight: clamp(num(p.weight, 0.5), 0, 1) })
    }
    return out.slice(0, 40)
}

// ── land mask: Natural Earth 1:50m land, equirectangular 720 × 360, row run-lengths (varint) in base64.
const MASK_W = 720
const MASK_H = 360
const MASK = "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"

let maskCache: Uint8Array | null = null
function landMask(): Uint8Array {
    if (maskCache) return maskCache
    const bin = typeof atob === "function" ? atob(MASK) : ""
    const out = new Uint8Array(MASK_W * MASK_H)
    let i = 0
    let pos = 0
    for (let y = 0; y < MASK_H; y++) {
        let x = 0
        let land = 0
        while (x < MASK_W && i < bin.length) {
            let v = 0
            let shift = 0
            let b = 0
            do {
                b = bin.charCodeAt(i++)
                v |= (b & 127) << shift
                shift += 7
            } while (b & 128)
            if (land) out.fill(1, pos + x, pos + x + v)
            x += v
            land ^= 1
        }
        pos += MASK_W
    }
    maskCache = out
    return out
}

function isLand(mask: Uint8Array, lat: number, lng: number): boolean {
    const row = clamp(Math.floor(((90 - lat) / 180) * MASK_H), 0, MASK_H - 1)
    const col = clamp(Math.floor(((lng + 180) / 360) * MASK_W), 0, MASK_W - 1)
    return mask[row * MASK_W + col] === 1
}

function pointCount(density: number): number {
    return Math.round(4000 + clamp(density, 10, 100) * 400)
}

// Fibonacci sphere, land points only. xyz with lng 0 facing +z, north +y.
const dotCache = new Map<number, Float32Array>()
function landDots(density: number): Float32Array {
    const n = pointCount(density)
    const hit = dotCache.get(n)
    if (hit) return hit
    const mask = landMask()
    const tmp: number[] = []
    const golden = Math.PI * (3 - Math.sqrt(5))
    for (let i = 0; i < n; i++) {
        const y = 1 - (2 * (i + 0.5)) / n
        const r = Math.sqrt(1 - y * y)
        const t = golden * i
        const x = r * Math.sin(t)
        const z = r * Math.cos(t)
        const lat = (Math.asin(y) * 180) / Math.PI
        const lng = (Math.atan2(x, z) * 180) / Math.PI
        if (isLand(mask, lat, lng)) tmp.push(x, y, z)
    }
    const arr = new Float32Array(tmp)
    dotCache.set(n, arr)
    return arr
}

type V3 = [number, number, number]
function toVec(lat: number, lng: number, r = 1): V3 {
    const phi = (lat * Math.PI) / 180
    const lam = (lng * Math.PI) / 180
    return [r * Math.cos(phi) * Math.sin(lam), r * Math.sin(phi), r * Math.cos(phi) * Math.cos(lam)]
}

// Great-circle arc lifted off the surface; the lift grows with distance.
function arcPoints(a: CleanPin, b: CleanPin, steps: number): V3[] {
    const p = toVec(a.lat, a.lng)
    const q = toVec(b.lat, b.lng)
    const dot = clamp(p[0] * q[0] + p[1] * q[1] + p[2] * q[2], -1, 1)
    const ang = Math.acos(dot)
    const lift = 0.06 + 0.32 * (ang / Math.PI)
    const s = Math.sin(ang) || 1e-6
    const out: V3[] = []
    for (let i = 0; i <= steps; i++) {
        const t = i / steps
        const w1 = ang < 1e-4 ? 1 - t : Math.sin((1 - t) * ang) / s
        const w2 = ang < 1e-4 ? t : Math.sin(t * ang) / s
        const r = 1 + lift * Math.sin(Math.PI * t)
        out.push([(w1 * p[0] + w2 * q[0]) * r, (w1 * p[1] + w2 * q[1]) * r, (w1 * p[2] + w2 * q[2]) * r])
    }
    return out
}

function arcPairs(pins: CleanPin[], mode: ArcMode): [CleanPin, CleanPin][] {
    if (mode === "off" || pins.length < 2) return []
    const out: [CleanPin, CleanPin][] = []
    if (mode === "hub") for (let i = 1; i < pins.length; i++) out.push([pins[0], pins[i]])
    else for (let i = 0; i + 1 < pins.length; i++) out.push([pins[i], pins[i + 1]])
    return out.slice(0, 24)
}

// Same rotation as the WebGL group: spin about Y, then tilt about X.
function rotate(v: V3, spin: number, tilt: number): V3 {
    const cb = Math.cos(spin)
    const sb = Math.sin(spin)
    const x1 = v[0] * cb + v[2] * sb
    const z1 = -v[0] * sb + v[2] * cb
    const ca = Math.cos(tilt)
    const sa = Math.sin(tilt)
    return [x1, v[1] * ca - z1 * sa, v[1] * sa + z1 * ca]
}

const rad = (d: number) => (d * Math.PI) / 180

function describe(p: Props, pins: CleanPin[]): string {
    if (p.label.trim()) return p.label.trim()
    const names = pins.map((q) => q.label).filter(Boolean)
    return names.length ? `Globe marking ${names.join(", ")}` : "Dotted globe"
}

// Screen-space box [x0, y0, x1, y1] used to keep labels apart.
type Box = [number, number, number, number]
const overlaps = (a: Box, b: Box, pad: number) => a[0] < b[2] + pad && b[0] < a[2] + pad && a[1] < b[3] + pad && b[1] < a[3] + pad

// ── flat globe: static renderer, first paint and no-WebGL fallback. Orthographic projection of the same dots.
const VB = 1000
function FlatGlobe({ p, pins, showLabels }: { p: Props; pins: CleanPin[]; showLabels: boolean }) {
    const g = p.globe
    const R = (VB / 2) * (clamp(num(g.size, 78), 20, 100) / 100)
    const c = VB / 2
    const spin = -rad(num(p.motion.startLng, 10))
    const tilt = rad(clamp(num(p.motion.tilt, 22), -60, 60))
    const dots = landDots(num(g.density, 55))
    const spacing = R * Math.sqrt((4 * Math.PI) / pointCount(num(g.density, 55)))
    const dotD = Math.max(0.6, spacing * (clamp(num(g.dotSize, 60), 10, 100) / 100))
    const buckets = ["", "", ""]
    for (let i = 0; i < dots.length; i += 3) {
        const v = rotate([dots[i], dots[i + 1], dots[i + 2]], spin, tilt)
        if (v[2] <= 0) continue
        const b = v[2] > 0.5 ? 2 : v[2] > 0.2 ? 1 : 0
        buckets[b] += `M${(c + v[0] * R).toFixed(1)} ${(c - v[1] * R).toFixed(1)}h0`
    }
    const dotColor = cssColor(g.dotColor, DEFAULT_GLOBE.dotColor as string)
    const ocean = cssColor(g.oceanColor, DEFAULT_GLOBE.oceanColor as string)
    const glowColor = cssColor(g.glowColor, DEFAULT_GLOBE.glowColor as string)
    const glow = clamp(num(g.glow, 60), 0, 100) / 100
    const pinColor = cssColor(p.markers.color, DEFAULT_MARKERS.color as string)
    const arcColor = cssColor(p.arcs.color, DEFAULT_ARCS.color as string)
    const pinR = spacing * 0.95 * (clamp(num(p.markers.size, 100), 40, 250) / 100)
    const arcs = arcPairs(pins, p.arcs.mode).map(([a, b]) => {
        let d = ""
        let pen = false
        for (const q of arcPoints(a, b, 48)) {
            const v = rotate(q, spin, tilt)
            const vis = v[2] > 0 || v[0] * v[0] + v[1] * v[1] > 1
            if (vis) {
                d += `${pen ? "L" : "M"}${(c + v[0] * R).toFixed(1)} ${(c - v[1] * R).toFixed(1)}`
                pen = true
            } else pen = false
        }
        return d
    })
    const shown = pins
        .map((q) => ({ q, v: rotate(toVec(q.lat, q.lng), spin, tilt) }))
        .filter((o) => o.v[2] > 0.08)
    const fs = VB * 0.024
    // Same rule as the live globe: first pins win, a label that would overlap
    // another label (or run off the edge) moves to the other side or is dropped.
    const taken: Box[] = []
    const placedLabel = shown.map(({ q, v }) => {
        if (!showLabels || !q.label) return null
        const x = c + v[0] * R
        const y = c - v[1] * R
        const w = fs * 0.6 * q.label.length
        const sides = x < c + R * 0.55 ? [1, -1] : [-1, 1]
        for (const s of sides) {
            const x0 = s > 0 ? x + pinR * 2.4 : x - pinR * 2.4 - w
            const b: Box = [x0, y - fs * 0.6, x0 + w, y + fs * 0.6]
            if (b[0] < 0 || b[2] > VB || taken.some((t) => overlaps(t, b, 6))) continue
            taken.push(b)
            return s
        }
        return null
    })
    return (
        <svg className="adg-flat" viewBox={`0 0 ${VB} ${VB}`} preserveAspectRatio="xMidYMid meet" aria-hidden="true" focusable="false">
            <defs>
                <radialGradient id="adg-glow" cx="50%" cy="50%" r="50%">
                    <stop offset={`${((R / (R * 1.22)) * 100).toFixed(1)}%`} stopColor={glowColor} stopOpacity={0.55 * glow} />
                    <stop offset="100%" stopColor={glowColor} stopOpacity={0} />
                </radialGradient>
                <radialGradient id="adg-sea" cx="42%" cy="36%" r="70%">
                    <stop offset="0%" stopColor={ocean} stopOpacity={1} />
                    <stop offset="100%" stopColor={ocean} stopOpacity={1} />
                </radialGradient>
            </defs>
            {glow > 0 ? <circle cx={c} cy={c} r={R * 1.22} fill="url(#adg-glow)" /> : null}
            <circle cx={c} cy={c} r={R} fill={ocean} fillOpacity={clamp(num(g.oceanOpacity, 85), 0, 100) / 100} />
            <g fill="none" stroke={dotColor} strokeLinecap="round" strokeWidth={dotD}>
                <path d={buckets[0]} strokeOpacity={0.35} />
                <path d={buckets[1]} strokeOpacity={0.7} />
                <path d={buckets[2]} strokeOpacity={1} />
            </g>
            <g fill="none" stroke={arcColor} strokeWidth={Math.max(1.2, R * 0.006)} strokeLinecap="round" strokeOpacity={0.75}>
                {arcs.map((d, i) => (d ? <path key={i} d={d} /> : null))}
            </g>
            {shown.map(({ q, v }, i) => {
                const x = c + v[0] * R
                const y = c - v[1] * R
                const side = placedLabel[i]
                const right = side === 1
                return (
                    <g key={i}>
                        <circle cx={x} cy={y} r={pinR * 2.1} fill={pinColor} fillOpacity={0.22} />
                        <circle cx={x} cy={y} r={pinR} fill={pinColor} />
                        {side ? (
                            <text
                                x={right ? x + pinR * 2.4 : x - pinR * 2.4}
                                y={y + fs * 0.35}
                                textAnchor={right ? "start" : "end"}
                                fontSize={fs}
                                fontWeight={600}
                                fill={cssColor(p.markers.labelColor, DEFAULT_MARKERS.labelColor as string)}
                                className="adg-svgtext"
                            >
                                {q.label}
                            </text>
                        ) : null}
                    </g>
                )
            })}
        </svg>
    )
}

// ── WebGL engine
const DOT_VERT = `
uniform float uSize;
uniform float uPixel;
varying float vFacing;
void main() {
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vFacing = normalize(mat3(modelViewMatrix) * position).z;
    gl_PointSize = uSize * uPixel;
    gl_Position = projectionMatrix * mv;
}`
const DOT_FRAG = `
uniform vec3 uColor;
uniform float uBack;
varying float vFacing;
void main() {
    vec2 d = gl_PointCoord - 0.5;
    float r = length(d);
    float edge = smoothstep(0.5, 0.36, r);
    float a = vFacing > 0.0 ? mix(0.3, 1.0, smoothstep(0.0, 0.55, vFacing)) : uBack * smoothstep(-1.0, -0.2, vFacing);
    if (a * edge < 0.01) discard;
    gl_FragColor = vec4(uColor, a * edge);

    ${CS_CHUNK}
}`
const PIN_VERT = `
attribute float aPhase;
uniform float uSize;
uniform float uPixel;
uniform float uTime;
uniform float uRing;
varying float vFacing;
varying float vT;
void main() {
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vFacing = normalize(mat3(modelViewMatrix) * position).z;
    vT = fract(uTime * 0.55 + aPhase);
    float s = uRing > 0.5 ? uSize * (1.2 + 3.2 * vT) : uSize;
    gl_PointSize = s * uPixel;
    gl_Position = projectionMatrix * mv;
}`
const PIN_FRAG = `
uniform vec3 uColor;
uniform float uRing;
uniform float uPulse;
varying float vFacing;
varying float vT;
void main() {
    vec2 d = gl_PointCoord - 0.5;
    float r = length(d);
    float vis = smoothstep(0.02, 0.18, vFacing);
    float a;
    if (uRing > 0.5) {
        float ring = smoothstep(0.5, 0.42, r) * smoothstep(0.3, 0.42, r);
        a = ring * (1.0 - vT) * 0.8 * uPulse;
    } else {
        float core = smoothstep(0.5, 0.38, r);
        float halo = smoothstep(0.5, 0.0, r) * 0.35;
        a = max(core, halo);
    }
    a *= vis;
    if (a < 0.01) discard;
    gl_FragColor = vec4(uColor, a);

    ${CS_CHUNK}
}`
const ARC_VERT = `
attribute float aU;
varying float vU;
varying float vFacing;
varying float vOut;
void main() {
    vU = aU;
    vec3 n = normalize(mat3(modelViewMatrix) * position);
    vFacing = n.z;
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vOut = length(mv.xy);
    gl_Position = projectionMatrix * mv;
}`
const ARC_FRAG = `
uniform vec3 uColor;
uniform float uTime;
uniform float uOff;
uniform float uAnim;
uniform float uEmph;
varying float vU;
varying float vFacing;
varying float vOut;
void main() {
    float vis = max(smoothstep(-0.02, 0.12, vFacing), smoothstep(1.0, 1.03, vOut));
    float a = uAnim > 0.5 ? 0.32 : 0.7;
    if (uAnim > 0.5) {
        float head = fract(uTime + uOff) * 1.3;
        float dd = head - vU;
        float tail = dd >= 0.0 && dd < 0.3 ? 1.0 - dd / 0.3 : 0.0;
        a += tail * tail * 0.95;
    }
    a = min(1.0, a * vis * uEmph);
    if (a < 0.01) discard;
    gl_FragColor = vec4(uColor, a);

    ${CS_CHUNK}
}`
const OCEAN_VERT = `
varying float vFacing;
void main() {
    vFacing = normalize(mat3(modelViewMatrix) * normal).z;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}`
const OCEAN_FRAG = `
uniform vec3 uColor;
uniform vec3 uRim;
uniform float uOpacity;
uniform float uGlow;
varying float vFacing;
void main() {
    float rim = pow(1.0 - clamp(vFacing, 0.0, 1.0), 3.0);
    vec3 c = mix(uColor, uRim, rim * 0.55 * uGlow);
    gl_FragColor = vec4(c, uOpacity);

    ${CS_CHUNK}
}`
const GLOW_VERT = `
varying vec2 vP;
void main() {
    vP = position.xy;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}`
const GLOW_FRAG = `
uniform vec3 uColor;
uniform float uStrength;
varying vec2 vP;
void main() {
    float r = length(vP);
    float a = r < 0.97 ? 0.0 : exp(-max(r - 1.0, 0.0) * 9.0) * (1.0 - smoothstep(1.28, 1.35, r));
    a *= uStrength;
    if (a < 0.003) discard;
    gl_FragColor = vec4(uColor, a);
    ${CS_CHUNK}
}`

type Look = {
    dot: string
    dotSize: number
    density: number
    size: number
    ocean: string
    oceanOpacity: number
    glow: string
    glowStrength: number
    pin: string
    pinSize: number
    pulse: boolean
    arcColor: string
    arcSpeed: number
}
type Motion3D = { autoRotate: boolean; speed: number; drag: boolean; startLng: number; tilt: number; reduce: boolean }

interface LabelSlot {
    el: HTMLSpanElement
    pos: THREE.Vector3
    pin: number
    // measured size (0 = measure again) and the side it was last shown on
    w: number
    h: number
    side: number
    // where it is drawn now (for clicks), null while hidden
    box: Box | null
}

interface ArcSlot {
    mesh: THREE.Mesh
    mat: THREE.ShaderMaterial
    pts: V3[]
    pin: number
}

const ZOOM_MIN = 1
const ZOOM_MAX = 5

// Tube along an arc; `aU` runs 0..1 from start to end for the travelling head.
function arcTube(pts: V3[], radius: number): THREE.TubeGeometry {
    const curve = new THREE.CatmullRomCurve3(pts.map((v) => new THREE.Vector3(v[0], v[1], v[2])))
    const geo = new THREE.TubeGeometry(curve, 96, radius, 5, false)
    const uv = geo.getAttribute("uv") as THREE.BufferAttribute
    const u = new Float32Array(uv.count)
    for (let k = 0; k < uv.count; k++) u[k] = uv.getX(k)
    geo.attributes.aU = new THREE.BufferAttribute(u, 1)
    return geo
}

const seg2 = (px: number, py: number, ax: number, ay: number, bx: number, by: number) => {
    const dx = bx - ax
    const dy = by - ay
    const L = dx * dx + dy * dy
    const t = L ? clamp(((px - ax) * dx + (py - ay) * dy) / L, 0, 1) : 0
    const x = ax + t * dx - px
    const y = ay + t * dy - py
    return x * x + y * y
}

class GlobeEngine {
    private renderer: THREE.WebGLRenderer
    private drawFailed = false
    private scene = new THREE.Scene()
    private camera = new THREE.OrthographicCamera(-1, 1, 1, -1, -10, 10)
    private globe = new THREE.Group()
    private dotsGeo = new THREE.BufferGeometry()
    private dotsMat: THREE.ShaderMaterial
    private dots: THREE.Points
    private ocean: THREE.Mesh
    private oceanMat: THREE.ShaderMaterial
    private glowMesh: THREE.Mesh
    private glowMat: THREE.ShaderMaterial
    private pinGeo = new THREE.BufferGeometry()
    private pinMat: THREE.ShaderMaterial
    private ringMat: THREE.ShaderMaterial
    private pinPoints: THREE.Points
    private ringPoints: THREE.Points
    // the selected pin: a larger dot with its own, always pulsing ring
    private selGeo = new THREE.BufferGeometry()
    private selCoreMat: THREE.ShaderMaterial
    private selRingMat: THREE.ShaderMaterial
    private selCore: THREE.Points
    private selRing: THREE.Points
    private arcs: ArcSlot[] = []
    private labels: LabelSlot[] = []
    private look: Look | null = null
    private motion: Motion3D = { autoRotate: true, speed: 6, drag: true, startLng: 10, tilt: 22, reduce: false }
    private pins: CleanPin[] = []
    private arcMode: ArcMode = "hub"
    private showLabels = true
    private density = -1
    // orientation (radians)
    private spin = 0
    private spinTarget: number | null = null
    private tilt = 0
    private tiltTarget = 0
    private vel = 0
    private auto = 0 // 0..1 blend of auto-rotation
    private hover = false
    private focused = false
    // zoom (1 = whole globe) and the arc thickness step it was built for
    private zoom = 1
    private zoomTarget = 1
    private arcStep = 0
    // selection / hover (pin index, -1 = none)
    private selected = -1
    private hovered = -1
    // time
    private time = 0
    private raf = 0
    private last = 0
    private width = 1
    private height = 1
    private radiusPx = 1
    private fontPx = 12
    private pinPx = 6
    private visible = false
    private disposed = false
    private ro: ResizeObserver | null = null
    private io: IntersectionObserver | null = null
    // pointer
    private dragging = false
    private pointerId = -1
    private lastX = 0
    private lastY = 0
    private lastT = 0
    private downId = -1
    private downX = 0
    private downY = 0
    private downT = 0
    private touches = new Map<number, { x: number; y: number }>()
    private pinch: { d: number; z: number } | null = null
    private tmp = new THREE.Vector3()

    constructor(
        private canvas: HTMLCanvasElement,
        private root: HTMLElement,
        private labelLayer: HTMLElement,
        gl: WebGL2RenderingContext,
        private onReady: (ready: boolean) => void,
        private onRestored: () => void,
        private onPick: (pin: number) => void
    ) {
        this.renderer = new THREE.WebGLRenderer({ canvas, context: gl, antialias: true, alpha: true })
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
        this.renderer.setClearColor(0x000000, 0)
        this.camera.position.set(0, 0, 5)
        this.camera.lookAt(0, 0, 0)

        this.glowMat = new THREE.ShaderMaterial({
            vertexShader: GLOW_VERT,
            fragmentShader: GLOW_FRAG,
            uniforms: { uColor: { value: new THREE.Color() }, uStrength: { value: 0.6 } },
            transparent: true,
            depthWrite: false,
            depthTest: false,
        })
        this.glowMesh = new THREE.Mesh(new THREE.PlaneGeometry(2.8, 2.8), this.glowMat)
        this.glowMesh.renderOrder = 0
        this.oceanMat = new THREE.ShaderMaterial({
            vertexShader: OCEAN_VERT,
            fragmentShader: OCEAN_FRAG,
            uniforms: { uColor: { value: new THREE.Color() }, uRim: { value: new THREE.Color() }, uOpacity: { value: 0.85 }, uGlow: { value: 0.6 } },
            transparent: true,
            depthWrite: false,
            depthTest: false,
        })
        this.ocean = new THREE.Mesh(new THREE.SphereGeometry(0.995, 64, 32), this.oceanMat)
        this.ocean.renderOrder = 1
        this.dotsMat = new THREE.ShaderMaterial({
            vertexShader: DOT_VERT,
            fragmentShader: DOT_FRAG,
            uniforms: { uColor: { value: new THREE.Color() }, uSize: { value: 2 }, uPixel: { value: 1 }, uBack: { value: 0.05 } },
            transparent: true,
            depthWrite: false,
            depthTest: false,
        })
        this.dots = new THREE.Points(this.dotsGeo, this.dotsMat)
        this.dots.renderOrder = 2
        const pinUniforms = () => ({
            uColor: { value: new THREE.Color() },
            uSize: { value: 6 },
            uPixel: { value: 1 },
            uTime: { value: 0 },
            uRing: { value: 0 },
            uPulse: { value: 1 },
        })
        const pinMaterial = (ring: boolean) => {
            const m = new THREE.ShaderMaterial({ vertexShader: PIN_VERT, fragmentShader: PIN_FRAG, uniforms: pinUniforms(), transparent: true, depthWrite: false, depthTest: false })
            m.uniforms.uRing.value = ring ? 1 : 0
            return m
        }
        this.pinMat = pinMaterial(false)
        this.ringMat = pinMaterial(true)
        this.selCoreMat = pinMaterial(false)
        this.selRingMat = pinMaterial(true)
        this.pinPoints = new THREE.Points(this.pinGeo, this.pinMat)
        this.ringPoints = new THREE.Points(this.pinGeo, this.ringMat)
        this.pinPoints.renderOrder = 5
        this.ringPoints.renderOrder = 4
        this.selGeo.attributes.position = new THREE.BufferAttribute(new Float32Array(3), 3)
        this.selGeo.attributes.aPhase = new THREE.BufferAttribute(new Float32Array(1), 1)
        this.selCore = new THREE.Points(this.selGeo, this.selCoreMat)
        this.selRing = new THREE.Points(this.selGeo, this.selRingMat)
        this.selCore.renderOrder = 7
        this.selRing.renderOrder = 6
        this.selCore.visible = false
        this.selRing.visible = false
        this.globe.add(this.ocean, this.dots, this.ringPoints, this.pinPoints, this.selRing, this.selCore)
        this.scene.add(this.glowMesh, this.globe)

        root.addEventListener("pointerdown", this.onDown)
        root.addEventListener("pointermove", this.onMove)
        root.addEventListener("pointerup", this.onUp)
        root.addEventListener("pointercancel", this.onUp)
        root.addEventListener("pointerenter", this.onEnter)
        root.addEventListener("pointerleave", this.onLeave)
        root.addEventListener("wheel", this.onWheel, { passive: false })
        root.addEventListener("keydown", this.onKey)
        root.addEventListener("focus", this.onFocus)
        root.addEventListener("blur", this.onBlur)
        canvas.addEventListener("webglcontextlost", this.onLost)
        canvas.addEventListener("webglcontextrestored", this.onRestore)
        this.ro = new ResizeObserver(() => this.resize())
        this.ro.observe(root)
        this.io = new IntersectionObserver(
            (entries) => {
                const e = entries[entries.length - 1]
                this.visible = !!e && e.isIntersecting
                if (this.visible) this.invalidate()
                else this.stop()
            },
            { threshold: [0, 0.01] }
        )
        this.io.observe(root)
        this.resize()
    }

    // ── public API
    setLook(look: Look) {
        const prev = this.look
        this.look = look
        this.dotsMat.uniforms.uColor.value.set(look.dot)
        this.oceanMat.uniforms.uColor.value.set(look.ocean)
        this.oceanMat.uniforms.uRim.value.set(look.glow)
        this.oceanMat.uniforms.uOpacity.value = look.oceanOpacity
        this.oceanMat.uniforms.uGlow.value = look.glowStrength
        this.ocean.visible = look.oceanOpacity > 0.001
        this.dotsMat.uniforms.uBack.value = 0.28 * (1 - look.oceanOpacity)
        this.glowMat.uniforms.uColor.value.set(look.glow)
        this.glowMat.uniforms.uStrength.value = 0.7 * look.glowStrength
        this.glowMesh.visible = look.glowStrength > 0.001
        for (const m of [this.pinMat, this.ringMat, this.selCoreMat, this.selRingMat]) m.uniforms.uColor.value.set(look.pin)
        this.ringMat.uniforms.uPulse.value = look.pulse ? 1 : 0
        for (const a of this.arcs) a.mat.uniforms.uColor.value.set(look.arcColor)
        if (!prev || prev.density !== look.density) this.buildDots(look.density)
        if (!prev || prev.size !== look.size) this.resize()
        else this.updateSizes()
        this.invalidate()
    }

    setMotion(m: Motion3D) {
        const prev = this.motion
        const first = !this.motionSet
        this.motionSet = true
        this.motion = m
        if (first || prev.startLng !== m.startLng) {
            this.spin = -rad(m.startLng)
            this.vel = 0
        }
        if (first || prev.tilt !== m.tilt) {
            this.tiltTarget = rad(clamp(m.tilt, -60, 60))
            if (first) this.tilt = this.tiltTarget
        }
        if (first) this.auto = m.autoRotate && !m.reduce ? 1 : 0
        this.root.style.touchAction = m.drag ? "pan-y" : ""
        this.root.style.cursor = m.drag ? "grab" : ""
        this.invalidate()
    }
    private motionSet = false

    setData(pins: CleanPin[], mode: ArcMode, labels: boolean) {
        this.pins = pins
        this.arcMode = mode
        this.showLabels = labels
        // pins
        const pos = new Float32Array(pins.length * 3)
        const phase = new Float32Array(pins.length)
        pins.forEach((p, i) => {
            const v = toVec(p.lat, p.lng, 1.004)
            pos.set(v, i * 3)
            phase[i] = (i * 0.37) % 1
        })
        this.pinGeo.dispose()
        this.pinGeo = new THREE.BufferGeometry()
        this.pinGeo.attributes.position = new THREE.BufferAttribute(pos, 3)
        this.pinGeo.attributes.aPhase = new THREE.BufferAttribute(phase, 1)
        this.pinPoints.geometry = this.pinGeo
        this.ringPoints.geometry = this.pinGeo
        // labels (own layer only)
        const layer = this.labelLayer
        for (const l of this.labels) l.el.remove()
        this.labels = []
        if (labels) {
            pins.forEach((p, i) => {
                if (!p.label) return
                const el = document.createElement("span")
                el.className = "adg-label"
                el.textContent = p.label
                layer.append(el)
                const v = toVec(p.lat, p.lng, 1.004)
                this.labels.push({ el, pos: new THREE.Vector3(v[0], v[1], v[2]), pin: i, w: 0, h: 0, side: 0, box: null })
            })
        }
        // a selection that no longer exists is dropped; one that does is re-marked
        const sel = this.selected
        this.selected = -1
        this.setSelected(sel < pins.length ? sel : -1, false)
        this.buildArcs()
        this.updateSizes()
        this.invalidate()
    }

    /** Select pin `i` (>= 1; -1 clears). `focus` turns and zooms to show its link. */
    setSelected(i: number, focus = true) {
        const sel = i >= 1 && i < this.pins.length ? i : -1
        if (sel === this.selected) {
            if (sel >= 0 && focus) this.focusLink(sel)
            return
        }
        this.selected = sel
        if (sel >= 0) {
            const p = this.pins[sel]
            const pos = this.selGeo.getAttribute("position") as THREE.BufferAttribute
            pos.set(toVec(p.lat, p.lng, 1.004))
            pos.needsUpdate = true
        }
        this.selCore.visible = sel >= 0
        for (const l of this.labels) {
            l.el.classList.toggle("adg-label-sel", l.pin === sel)
            l.w = 0
        }
        if (this.pins.length) this.buildArcs()
        if (focus) {
            if (sel >= 0) this.focusLink(sel)
            else this.zoomTarget = ZOOM_MIN
        }
        this.invalidate()
    }

    zoomBy(f: number) {
        this.setZoom(this.zoomTarget * f, false)
    }

    /** Back to the starting view: whole globe, start longitude and tilt. */
    reset() {
        this.vel = 0
        this.spinTarget = this.nearSpin(-rad(this.motion.startLng))
        this.tiltTarget = rad(clamp(this.motion.tilt, -60, 60))
        this.zoomTarget = ZOOM_MIN
        if (this.motion.reduce) this.settle()
        this.invalidate()
    }

    dispose() {
        this.disposed = true
        this.stop()
        this.ro?.disconnect()
        this.io?.disconnect()
        const r = this.root
        r.removeEventListener("pointerdown", this.onDown)
        r.removeEventListener("pointermove", this.onMove)
        r.removeEventListener("pointerup", this.onUp)
        r.removeEventListener("pointercancel", this.onUp)
        r.removeEventListener("pointerenter", this.onEnter)
        r.removeEventListener("pointerleave", this.onLeave)
        r.removeEventListener("wheel", this.onWheel)
        r.removeEventListener("keydown", this.onKey)
        r.removeEventListener("focus", this.onFocus)
        r.removeEventListener("blur", this.onBlur)
        r.style.touchAction = ""
        r.style.cursor = ""
        this.canvas.removeEventListener("webglcontextlost", this.onLost)
        this.canvas.removeEventListener("webglcontextrestored", this.onRestore)
        for (const l of this.labels) l.el.remove()
        this.labels = []
        for (const a of this.arcs) {
            a.mesh.geometry.dispose()
            a.mat.dispose()
        }
        this.dotsGeo.dispose()
        this.pinGeo.dispose()
        this.selGeo.dispose()
        this.ocean.geometry.dispose()
        this.glowMesh.geometry.dispose()
        for (const m of [this.dotsMat, this.pinMat, this.ringMat, this.selCoreMat, this.selRingMat, this.oceanMat, this.glowMat]) m.dispose()
        this.renderer.dispose()
    }

    // ── build
    private buildDots(density: number) {
        if (density === this.density) return
        this.density = density
        const arr = landDots(density)
        this.dotsGeo.dispose()
        this.dotsGeo = new THREE.BufferGeometry()
        this.dotsGeo.attributes.position = new THREE.BufferAttribute(arr, 3)
        this.dots.geometry = this.dotsGeo
        this.updateSizes()
    }

    // Arcs are tubes in globe units, so zooming in would fatten them: they are
    // rebuilt thinner in steps as the zoom grows, and the selected one thicker.
    private buildArcs() {
        for (const a of this.arcs) {
            this.globe.remove(a.mesh)
            a.mesh.geometry.dispose()
            a.mat.dispose()
        }
        this.arcs = []
        this.arcStep = this.zoomStep()
        const thin = Math.pow(1.3, -0.7 * this.arcStep)
        arcPairs(this.pins, this.arcMode).forEach(([a, b], i) => {
            const pin = i + 1
            const pts = arcPoints(a, b, 64)
            const weight = this.pins[pin] ? this.pins[pin].weight : 0.5
            const r = (0.0024 + 0.0046 * weight) * thin * (pin === this.selected ? 1.9 : 1)
            const mat = new THREE.ShaderMaterial({
                vertexShader: ARC_VERT,
                fragmentShader: ARC_FRAG,
                uniforms: {
                    uColor: { value: new THREE.Color(this.look ? this.look.arcColor : "#FFB35C") },
                    uTime: { value: 0 },
                    uOff: { value: (i * 0.29) % 1 },
                    uAnim: { value: 1 },
                    uEmph: { value: 1 },
                },
                transparent: true,
                depthWrite: false,
                depthTest: false,
            })
            const mesh = new THREE.Mesh(arcTube(pts, r), mat)
            mesh.renderOrder = 3
            this.globe.add(mesh)
            this.arcs.push({ mesh, mat, pts, pin })
        })
        this.applyEmphasis()
    }

    private zoomStep() {
        return Math.round(Math.log(this.zoom) / Math.log(1.3))
    }

    // With a selection, its link is bright and the rest fade back; hover previews.
    private applyEmphasis() {
        const sel = this.selected
        const hov = this.hovered
        for (const a of this.arcs) {
            let e = 1
            if (sel >= 0) e = a.pin === sel ? 2.2 : a.pin === hov ? 0.7 : 0.22
            else if (hov >= 0) e = a.pin === hov ? 2 : 0.5
            a.mat.uniforms.uEmph.value = e
        }
    }

    // The spin angle equal to `t` (mod 2π) nearest the current one: no long way round.
    private nearSpin(t: number) {
        const two = Math.PI * 2
        return t + Math.round((this.spin - t) / two) * two
    }

    // Turn so the middle of the hub → pin link faces the viewer and zoom so the
    // whole link fits: in this orthographic view a point θ from the centre sits
    // sin(θ) · R · zoom from it.
    private focusLink(i: number) {
        const p = this.pins[i]
        const hub = this.arcMode === "chain" ? this.pins[i - 1] : this.pins[0]
        if (!p || !hub) return
        const a = toVec(hub.lat, hub.lng)
        const b = toVec(p.lat, p.lng)
        let m: V3 = [a[0] + b[0], a[1] + b[1], a[2] + b[2]]
        const len = Math.hypot(m[0], m[1], m[2])
        m = len < 1e-3 ? b : [m[0] / len, m[1] / len, m[2] / len]
        const lat = Math.asin(clamp(m[1], -1, 1))
        const lng = Math.atan2(m[0], m[2])
        const ang = Math.acos(clamp(a[0] * b[0] + a[1] * b[1] + a[2] * b[2], -1, 1))
        const size = this.look ? this.look.size : 0.78
        const z = 0.7 / (size * Math.max(0.06, Math.sin(ang / 2)))
        this.vel = 0
        this.spinTarget = this.nearSpin(-lng)
        this.tiltTarget = clamp(lat, rad(-60), rad(60))
        this.zoomTarget = clamp(z, ZOOM_MIN, 4)
        if (this.motion.reduce) this.settle()
    }

    // Reduced motion: jump straight to where an animation would end.
    private settle() {
        if (this.spinTarget !== null) this.spin = this.spinTarget
        this.spinTarget = null
        this.tilt = this.tiltTarget
        this.zoom = this.zoomTarget
        this.applyZoom()
    }

    private setZoom(z: number, now: boolean) {
        this.zoomTarget = clamp(z, ZOOM_MIN, ZOOM_MAX)
        if (now || this.motion.reduce) {
            this.zoom = this.zoomTarget
            this.applyZoom()
        }
        this.invalidate()
    }

    private applyZoom() {
        this.applyCamera()
        this.updateSizes()
        if (this.zoomStep() !== this.arcStep && this.pins.length) this.buildArcs()
    }

    private resize() {
        if (this.disposed) return
        const w = Math.max(1, this.root.clientWidth)
        const h = Math.max(1, this.root.clientHeight)
        this.width = w
        this.height = h
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
        this.renderer.setSize(w, h, false)
        const size = this.look ? this.look.size : 0.78
        this.radiusPx = (Math.min(w, h) / 2) * size
        this.applyCamera()
        this.updateSizes()
        this.draw()
    }

    private applyCamera() {
        const s = this.radiusPx * this.zoom
        const w = this.width
        const h = this.height
        this.camera.left = -w / 2 / s
        this.camera.right = w / 2 / s
        this.camera.top = h / 2 / s
        this.camera.bottom = -h / 2 / s
        this.camera.updateProjectionMatrix()
    }

    private updateSizes() {
        const look = this.look
        if (!look) return
        const px = this.renderer.getPixelRatio()
        const unit = this.radiusPx * Math.sqrt((4 * Math.PI) / pointCount(look.density))
        // land dots spread out with the zoom but grow less than it, so close up the map stays fine-grained
        const d = Math.max(0.8, unit * Math.pow(this.zoom, 0.6) * look.dotSize)
        this.dotsMat.uniforms.uSize.value = d
        this.dotsMat.uniforms.uPixel.value = px
        const pinD = Math.max(5, unit * 2.6 * look.pinSize) * (1 + (this.zoom - 1) * 0.25)
        this.pinPx = pinD
        for (const m of [this.pinMat, this.ringMat]) {
            m.uniforms.uSize.value = pinD
            m.uniforms.uPixel.value = px
        }
        this.selCoreMat.uniforms.uSize.value = pinD * 1.5
        this.selRingMat.uniforms.uSize.value = pinD * 1.7
        for (const m of [this.selCoreMat, this.selRingMat]) m.uniforms.uPixel.value = px
        const fs = clamp(Math.min(this.width, this.height) * 0.024, 11, 18)
        if (Math.abs(fs - this.fontPx) > 0.05) {
            this.fontPx = fs
            for (const l of this.labels) l.w = 0
        }
        this.labelLayer.style.fontSize = `${fs.toFixed(1)}px`
    }

    // ── loop
    private autoTarget() {
        const m = this.motion
        const busy = this.hover || this.focused || this.dragging || this.pinch !== null
        return m.autoRotate && !m.reduce && !busy && this.selected < 0 && this.zoomTarget <= ZOOM_MIN + 0.001 && this.spinTarget === null ? 1 : 0
    }

    private animating(): boolean {
        const m = this.motion
        const autoTarget = this.autoTarget()
        if (this.dragging) return true
        if (Math.abs(this.vel) > 0.002) return true
        if (Math.abs(this.auto - autoTarget) > 0.002) return true
        if (autoTarget > 0) return true
        if (Math.abs(this.tilt - this.tiltTarget) > 0.0005) return true
        if (this.spinTarget !== null) return true
        if (Math.abs(this.zoom - this.zoomTarget) > 0.0005) return true
        if (!m.reduce && this.arcs.length > 0) return true
        if (!m.reduce && this.selected >= 0) return true
        return false
    }

    private invalidate() {
        if (this.disposed) return
        if (!this.visible) {
            this.draw()
            return
        }
        if (this.raf) return
        this.last = 0
        this.raf = requestAnimationFrame(this.tick)
    }

    private stop() {
        if (this.raf) cancelAnimationFrame(this.raf)
        this.raf = 0
    }

    private tick = (t: number) => {
        this.raf = 0
        if (this.disposed) return
        const dt = this.last ? Math.min(0.05, (t - this.last) / 1000) : 1 / 60
        this.last = t
        this.step(dt)
        const more = this.visible && this.animating()
        this.draw(more)
        if (more) this.raf = requestAnimationFrame(this.tick)
    }

    private step(dt: number) {
        const m = this.motion
        this.time += dt
        const autoTarget = this.autoTarget()
        const k = 1 - Math.exp(-dt * 2.2)
        this.auto += (autoTarget - this.auto) * k
        if (Math.abs(this.auto - autoTarget) < 0.002) this.auto = autoTarget
        if (!this.dragging) {
            if (this.spinTarget !== null) {
                this.vel = 0
                this.spin += (this.spinTarget - this.spin) * (1 - Math.exp(-dt * 4.5))
                if (Math.abs(this.spinTarget - this.spin) < 0.0008) {
                    this.spin = this.spinTarget
                    this.spinTarget = null
                }
            } else {
                this.spin += this.vel * dt
                this.vel *= Math.exp(-dt * 2.6)
                if (Math.abs(this.vel) < 0.002) this.vel = 0
                this.spin += rad(m.speed) * this.auto * dt
            }
        }
        this.tilt += (this.tiltTarget - this.tilt) * (1 - Math.exp(-dt * (this.spinTarget !== null ? 4.5 : 8)))
        if (Math.abs(this.tilt - this.tiltTarget) < 0.0005) this.tilt = this.tiltTarget
        if (this.zoom !== this.zoomTarget) {
            this.zoom += (this.zoomTarget - this.zoom) * (1 - Math.exp(-dt * 5))
            if (Math.abs(this.zoom - this.zoomTarget) < 0.0005) this.zoom = this.zoomTarget
            this.applyZoom()
        }
        if (this.spinTarget === null && (this.spin > Math.PI * 4 || this.spin < -Math.PI * 4)) this.spin %= Math.PI * 2
    }

    private draw(animating = false) {
        if (this.disposed) return
        const look = this.look
        if (!look) return
        this.globe.rotation.set(this.tilt, this.spin, 0, "XYZ")
        const live = animating && !this.motion.reduce
        const speed = 0.12 + (look.arcSpeed / 100) * 0.5
        for (const a of this.arcs) {
            a.mat.uniforms.uAnim.value = this.motion.reduce ? 0 : 1
            a.mat.uniforms.uTime.value = this.time * speed
        }
        this.ringMat.uniforms.uTime.value = this.time
        this.selRingMat.uniforms.uTime.value = this.time
        this.ringPoints.visible = live && look.pulse
        this.selRing.visible = live && this.selected >= 0
        // A draw that throws (shader or driver trouble) must not take the page down: stop drawing instead.
        if (this.drawFailed) return
        try {
            this.renderer.render(this.scene, this.camera)
        } catch {
            this.drawFailed = true
            return
        }
        this.placeLabels()
    }

    // Globe-space point → [x, y] in the frame, its facing (z) and whether it
    // lies outside the disc (arcs above the limb stay visible).
    private screen(v: V3): [number, number, number, boolean] {
        this.tmp.set(v[0], v[1], v[2]).applyMatrix4(this.globe.matrixWorld)
        const R = this.radiusPx * this.zoom
        const t = this.tmp
        return [this.width / 2 + t.x * R, this.height / 2 - t.y * R, t.z, t.x * t.x + t.y * t.y > 1]
    }

    private rank(pin: number) {
        return pin === this.selected ? -3 : pin === this.hovered ? -2 : pin === 0 ? -1 : pin
    }

    // Labels never overlap each other, a marker or the frame edge. In priority
    // order (selected, hovered, hub, then the pins as given = biggest first)
    // each label tries the side it used last, then the other; if neither is
    // free it fades out until rotation or zoom makes room.
    private placeLabels() {
        if (!this.labels.length) return
        this.globe.updateMatrixWorld()
        const w = this.width
        const h = this.height
        const mr = Math.max(3, this.pinPx * 0.42)
        const gap = Math.max(this.fontPx * 0.8, mr + 5)
        const at = this.pins.map((p) => this.screen(toVec(p.lat, p.lng, 1.004)))
        const taken: Box[] = []
        at.forEach(([x, y, z]) => {
            if (z > 0.05) taken.push([x - mr, y - mr, x + mr, y + mr])
        })
        const order = [...this.labels].sort((a, b) => this.rank(a.pin) - this.rank(b.pin))
        const R = Math.min(this.radiusPx * this.zoom, w / 2)
        for (const l of order) {
            const [x, y, z] = at[l.pin]
            const fade = clamp((z - 0.08) / 0.2, 0, 1)
            let box: Box | null = null
            if (fade > 0) {
                if (!l.w) {
                    l.w = l.el.offsetWidth
                    l.h = l.el.offsetHeight
                }
                const pref = l.side || (x > w / 2 + R * 0.55 ? -1 : 1)
                for (const s of [pref, -pref]) {
                    const x0 = s > 0 ? x + gap : x - gap - l.w
                    const b: Box = [x0, y - l.h / 2, x0 + l.w, y + l.h / 2]
                    if (b[0] < 2 || b[2] > w - 2 || b[1] < 2 || b[3] > h - 2) continue
                    // its own marker is in `taken` too, but the gap keeps clear of it
                    if (taken.some((t) => overlaps(t, b, 3))) continue
                    box = b
                    l.side = s
                    break
                }
            }
            l.box = box
            if (box) {
                taken.push(box)
                l.el.style.transform = `translate(${box[0].toFixed(1)}px, ${box[1].toFixed(1)}px)`
            }
            const dim = this.selected >= 0 && l.pin !== this.selected && l.pin !== 0 ? 0.5 : 1
            const op = box ? fade * dim : 0
            l.el.style.opacity = op.toFixed(3)
            l.el.style.visibility = fade > 0 ? "visible" : "hidden"
        }
    }

    // What is under a point in the frame: a label, a marker, or an arc (pin index, -1 = none).
    private pickAt(clientX: number, clientY: number): number {
        if (!this.pins.length) return -1
        const r = this.root.getBoundingClientRect()
        const x = clientX - r.left
        const y = clientY - r.top
        this.globe.updateMatrixWorld()
        for (const l of this.labels) {
            const b = l.box
            if (b && l.pin > 0 && x >= b[0] - 3 && x <= b[2] + 3 && y >= b[1] - 3 && y <= b[3] + 3) return l.pin
        }
        let best = -1
        let bd = Math.max(11, this.pinPx * 0.9) ** 2
        for (let i = 1; i < this.pins.length; i++) {
            const p = this.pins[i]
            const [px, py, pz] = this.screen(toVec(p.lat, p.lng, 1.004))
            if (pz < 0.05) continue
            const d = (px - x) ** 2 + (py - y) ** 2
            if (d < bd) {
                bd = d
                best = i
            }
        }
        if (best >= 0) return best
        let ad = 8 * 8
        for (const a of this.arcs) {
            let prev: [number, number] | null = null
            for (const v of a.pts) {
                const [sx, sy, sz, out] = this.screen(v)
                const vis = sz > -0.02 || out
                if (vis && prev) {
                    const d = seg2(x, y, prev[0], prev[1], sx, sy)
                    if (d < ad) {
                        ad = d
                        best = a.pin
                    }
                }
                prev = vis ? [sx, sy] : null
            }
        }
        return best
    }

    private hoverAt(clientX: number, clientY: number) {
        const i = this.pickAt(clientX, clientY)
        if (i === this.hovered) return
        this.hovered = i
        this.applyEmphasis()
        this.root.style.cursor = i >= 0 ? "pointer" : this.motion.drag ? "grab" : ""
        this.invalidate()
    }

    // ── input
    private onEnter = (e: PointerEvent) => {
        if (e.pointerType !== "mouse") return
        this.hover = true
        this.invalidate()
    }
    private onLeave = (e: PointerEvent) => {
        if (e.pointerType !== "mouse") return
        this.hover = false
        if (this.hovered >= 0) {
            this.hovered = -1
            this.applyEmphasis()
        }
        this.invalidate()
    }
    private onFocus = () => {
        this.focused = true
        this.invalidate()
    }
    private onBlur = () => {
        this.focused = false
        this.invalidate()
    }

    private onDown = (e: PointerEvent) => {
        if (e.pointerType === "mouse" && e.button !== 0) return
        this.downId = e.pointerId
        this.downX = e.clientX
        this.downY = e.clientY
        this.downT = e.timeStamp
        if (e.pointerType === "touch") {
            this.touches.set(e.pointerId, { x: e.clientX, y: e.clientY })
            if (this.touches.size === 2) {
                // second finger: pinch to zoom instead of turning
                const [a, b] = [...this.touches.values()]
                this.pinch = { d: Math.max(10, Math.hypot(a.x - b.x, a.y - b.y)), z: this.zoom }
                this.dragging = false
                this.pointerId = -1
                this.downId = -1
                this.invalidate()
                return
            }
        }
        if (!this.motion.drag) return
        this.dragging = true
        this.pointerId = e.pointerId
        this.lastX = e.clientX
        this.lastY = e.clientY
        this.lastT = e.timeStamp
        this.vel = 0
        this.root.style.cursor = "grabbing"
        try {
            this.root.setPointerCapture(e.pointerId)
        } catch {
            // capture is optional
        }
        this.invalidate()
    }

    private onMove = (e: PointerEvent) => {
        if (e.pointerType === "touch" && this.touches.has(e.pointerId)) {
            this.touches.set(e.pointerId, { x: e.clientX, y: e.clientY })
            if (this.pinch && this.touches.size >= 2) {
                const [a, b] = [...this.touches.values()]
                this.spinTarget = null
                this.setZoom((this.pinch.z * Math.hypot(a.x - b.x, a.y - b.y)) / this.pinch.d, true)
                return
            }
        }
        if (!this.dragging || e.pointerId !== this.pointerId) {
            if (!this.dragging && e.pointerType === "mouse") this.hoverAt(e.clientX, e.clientY)
            return
        }
        const dx = e.clientX - this.lastX
        const dy = e.clientY - this.lastY
        const dt = Math.max(1, e.timeStamp - this.lastT) / 1000
        // a real drag (not the jitter of a click) takes over from a focus animation
        if (this.spinTarget !== null && Math.hypot(e.clientX - this.downX, e.clientY - this.downY) > 5) this.spinTarget = null
        const per = 1 / Math.max(40, this.radiusPx * this.zoom)
        const dSpin = dx * per
        this.spin += dSpin
        this.vel = 0.65 * (dSpin / dt) + 0.35 * this.vel
        if (e.pointerType !== "touch") {
            this.tiltTarget = clamp(this.tiltTarget + dy * per, rad(-60), rad(60))
            this.tilt = this.tiltTarget
        }
        this.lastX = e.clientX
        this.lastY = e.clientY
        this.lastT = e.timeStamp
        this.invalidate()
    }

    private onUp = (e: PointerEvent) => {
        if (e.pointerType === "touch") {
            this.touches.delete(e.pointerId)
            if (this.pinch) {
                if (this.touches.size < 2) this.pinch = null
                this.invalidate()
                return
            }
        }
        const click =
            e.type === "pointerup" &&
            e.pointerId === this.downId &&
            Math.hypot(e.clientX - this.downX, e.clientY - this.downY) < 6 &&
            e.timeStamp - this.downT < 700
        this.downId = -1
        if (this.dragging && e.pointerId === this.pointerId) {
            this.dragging = false
            this.pointerId = -1
            // a pause before release means no fling; a click never flings
            if (click || e.timeStamp - this.lastT > 90) this.vel = 0
            this.vel = clamp(this.vel, -9, 9)
            this.root.style.cursor = this.motion.drag ? "grab" : ""
            try {
                this.root.releasePointerCapture(e.pointerId)
            } catch {
                // already released
            }
        }
        if (click) this.onPick(this.pickAt(e.clientX, e.clientY))
        this.invalidate()
    }

    // Ctrl/Cmd + wheel, and trackpad pinch (sent as ctrl + wheel), zoom; a plain
    // wheel keeps scrolling the page.
    private onWheel = (e: WheelEvent) => {
        if (!(e.ctrlKey || e.metaKey)) return
        e.preventDefault()
        const dy = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY
        this.spinTarget = null
        this.setZoom(this.zoomTarget * Math.exp(-clamp(dy, -120, 120) * 0.004), false)
    }

    private onKey = (e: KeyboardEvent) => {
        if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey) return
        let used = true
        if (e.key === "ArrowLeft") this.vel -= 1.4
        else if (e.key === "ArrowRight") this.vel += 1.4
        else if (e.key === "ArrowUp") this.tiltTarget = clamp(this.tiltTarget + rad(8), rad(-60), rad(60))
        else if (e.key === "ArrowDown") this.tiltTarget = clamp(this.tiltTarget - rad(8), rad(-60), rad(60))
        else if (e.key === "+" || e.key === "=") this.zoomBy(1.4)
        else if (e.key === "-" || e.key === "_") this.zoomBy(1 / 1.4)
        else if (e.key === "Escape" && this.selected >= 0) this.onPick(-1)
        else if (e.key === "Home") {
            this.reset()
            if (this.selected >= 0) this.onPick(-1)
        } else used = false
        if (!used) return
        e.preventDefault()
        if (e.key.startsWith("Arrow")) this.spinTarget = null
        this.vel = clamp(this.vel, -9, 9)
        this.invalidate()
    }

    private onLost = (e: Event) => {
        e.preventDefault()
        this.stop()
        this.onReady(false)
    }
    private onRestore = () => {
        this.onRestored()
    }

    ready() {
        this.draw()
        this.onReady(true)
    }
}

// ── component
const CSS = `
.adg-root { position: relative; overflow: hidden; outline: none; aspect-ratio: 1 / 1; font-family: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
.adg-root:focus-visible { box-shadow: inset 0 0 0 2px currentColor; }
.adg-flat { position: absolute; inset: 0; width: 100%; height: 100%; display: block; }
.adg-svgtext { paint-order: stroke; stroke: var(--adg-halo); stroke-width: 3px; stroke-linejoin: round; letter-spacing: 0.01em; }
.adg-canvas { position: absolute; inset: 0; width: 100%; height: 100%; display: block; opacity: 0; }
.adg-labels { position: absolute; inset: 0; pointer-events: none; opacity: 0; }
.adg-label { position: absolute; left: 0; top: 0; white-space: nowrap; font-weight: 600; line-height: 1; letter-spacing: 0.01em; text-shadow: 0 0 2px var(--adg-halo), 0 0 6px var(--adg-halo); will-change: transform; transition: opacity 0.18s ease; }
.adg-label-sel { padding: 0.32em 0.6em; border-radius: 999px; background: var(--adg-halo); text-shadow: none; font-weight: 700; box-shadow: 0 0 0 1px var(--adg-pin); }
.adg-ready .adg-canvas, .adg-ready .adg-labels { opacity: 1; }
.adg-ready .adg-flat { opacity: 0; }
.adg-live .adg-flat, .adg-live .adg-canvas, .adg-live .adg-labels { transition: opacity 0.4s ease; }
.adg-sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.adg-grab { user-select: none; -webkit-user-select: none; -webkit-tap-highlight-color: transparent; }
@media (prefers-reduced-motion: reduce) {
.adg-live .adg-flat, .adg-live .adg-canvas, .adg-live .adg-labels, .adg-label { transition: none; }
}
`

type FrameProps = { p: Props; pins: CleanPin[]; live: boolean; ready: boolean; rootRef?: { current: HTMLDivElement | null }; children?: ReactNode }

function Frame({ p, pins, live, ready, rootRef, children }: FrameProps) {
    const cls = "adg-root" + (live ? " adg-live" : "") + (live && p.motion.drag ? " adg-grab" : "") + (ready ? " adg-ready" : "")
    const bg = p.background.transparent ? "transparent" : cssColor(p.background.color, DEFAULT_BACKGROUND.color as string)
    return (
        <div
            ref={rootRef}
            className={cls}
            role="img"
            aria-label={describe(p, pins)}
            aria-roledescription={live && p.motion.drag ? "interactive globe" : undefined}
            tabIndex={live && p.motion.drag ? 0 : undefined}
            style={{
                ...p.style,
                background: bg,
                color: cssColor(p.markers.labelColor, DEFAULT_MARKERS.labelColor as string),
                ["--adg-pin" as string]: cssColor(p.markers.color, DEFAULT_MARKERS.color as string),
                ["--adg-halo" as string]: isDarkInk(glColor(p.markers.labelColor, DEFAULT_MARKERS.labelColor as string)) ? "rgba(255, 255, 255, 0.8)" : "rgba(0, 0, 0, 0.55)",
            }}
        >
            <style>{CSS}</style>
            <FlatGlobe p={p} pins={pins} showLabels={p.markers.labels} />
            {live && p.motion.drag ? <span className="adg-sr">Drag or use the arrow keys to turn the globe, plus and minus to zoom, Escape to clear the selection.</span> : null}
            {children}
        </div>
    )
}

/**
 * @framerIntrinsicWidth 600
 * @framerIntrinsicHeight 600
 * @framerSupportedLayoutWidth any-prefer-fixed
 * @framerSupportedLayoutHeight any-prefer-fixed
 */
export interface DotGlobeProps {
    /** Pins in decimal degrees. With arcs "hub", the FIRST pin is the hub every arc joins. Max 40. */
    pins?: Pin[]
    markers?: Partial<Markers>
    globe?: Partial<GlobeLook>
    arcs?: Partial<Arcs>
    motion?: Partial<Motion>
    background?: Partial<Background>
    /** Accessible name; empty = the pin labels are listed. */
    label?: string
    style?: CSSProperties
    /** Index of the selected pin (>= 1; the hub can't be selected), -1/undefined = none. */
    selected?: number
    /** Called with the pin index under a click or tap, -1 for empty space / Escape. */
    onSelect?: (index: number) => void
    /** Receives zoom / reset controls once the globe is running. */
    apiRef?: { current: DotGlobeApi | null }
}

export default function DotGlobe(props: DotGlobeProps) {
    const p = merge(props as Partial<Props>)
    const pins = cleanPins(p.pins)
    return <LiveGlobe p={p} pins={pins} selected={props.selected ?? -1} onSelect={props.onSelect} apiRef={props.apiRef} />
}

const useIsoLayoutEffect = typeof window !== "undefined" ? useLayoutEffect : useEffect

function useReduce(): boolean | null {
    const [reduce, setReduce] = useState<boolean | null>(null)
    useIsoLayoutEffect(() => {
        const mq = window.matchMedia("(prefers-reduced-motion: reduce)")
        const on = () => setReduce(mq.matches)
        on()
        mq.addEventListener("change", on)
        return () => mq.removeEventListener("change", on)
    }, [])
    return reduce
}

function LiveGlobe({ p, pins, selected, onSelect, apiRef }: { p: Props; pins: CleanPin[]; selected: number; onSelect?: (i: number) => void; apiRef?: { current: DotGlobeApi | null } }) {
    // the engine lives across renders; it calls the latest onSelect
    const pickRef = useRef(onSelect)
    pickRef.current = onSelect
    const reduce = useReduce()
    const rootRef = useRef<HTMLDivElement | null>(null)
    const canvasRef = useRef<HTMLCanvasElement | null>(null)
    const labelRef = useRef<HTMLDivElement | null>(null)
    const [mounted, setMounted] = useState(false)
    const [ready, setReady] = useState(false)
    const [failed, setFailed] = useState(false)
    const [engine, setEngine] = useState<GlobeEngine | null>(null)
    const [generation, setGeneration] = useState(0)

    useEffect(() => setMounted(true), [])

    useEffect(() => {
        const canvas = canvasRef.current
        const root = rootRef.current
        const layer = labelRef.current
        if (!mounted || !canvas || !root || !layer) return
        let gl: WebGL2RenderingContext | null = null
        try {
            gl = canvas.getContext("webgl2", { alpha: true, antialias: true, premultipliedAlpha: true })
        } catch {
            gl = null
        }
        if (!gl) {
            setFailed(true)
            return
        }
        let made: GlobeEngine | null = null
        try {
            made = new GlobeEngine(
                canvas,
                root,
                layer,
                gl,
                (r) => {
                    setReady(r)
                    if (!r) setFailed(true)
                },
                () => {
                    setFailed(false)
                    setGeneration((g) => g + 1)
                },
                (i) => pickRef.current?.(i)
            )
        } catch {
            made = null
        }
        if (!made) {
            setFailed(true)
            return
        }
        const current = made
        setEngine(current)
        return () => {
            current.dispose()
            setEngine(null)
            setReady(false)
        }
    }, [mounted, generation])

    const g = p.globe
    const m = p.markers
    const look: Look = {
        dot: glColor(g.dotColor, DEFAULT_GLOBE.dotColor as string),
        dotSize: clamp(num(g.dotSize, 60), 10, 100) / 100,
        density: clamp(num(g.density, 55), 10, 100),
        size: clamp(num(g.size, 78), 20, 100) / 100,
        ocean: glColor(g.oceanColor, DEFAULT_GLOBE.oceanColor as string),
        oceanOpacity: clamp(num(g.oceanOpacity, 85), 0, 100) / 100,
        glow: glColor(g.glowColor, DEFAULT_GLOBE.glowColor as string),
        glowStrength: clamp(num(g.glow, 60), 0, 100) / 100,
        pin: glColor(m.color, DEFAULT_MARKERS.color as string),
        pinSize: clamp(num(m.size, 100), 40, 250) / 100,
        pulse: !!m.pulse,
        arcColor: glColor(p.arcs.color, DEFAULT_ARCS.color as string),
        arcSpeed: clamp(num(p.arcs.speed, 50), 0, 100),
    }
    const lookKey = JSON.stringify(look)
    useEffect(() => {
        if (!engine) return
        engine.setLook(look)
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [engine, lookKey])

    const mo = p.motion
    useEffect(() => {
        if (!engine || reduce === null) return
        engine.setMotion({
            autoRotate: !!mo.autoRotate,
            speed: clamp(num(mo.speed, 6), 0, 60),
            drag: !!mo.drag,
            startLng: clamp(num(mo.startLng, 10), -180, 180),
            tilt: clamp(num(mo.tilt, 22), -60, 60),
            reduce,
        })
    }, [engine, reduce, mo.autoRotate, mo.speed, mo.drag, mo.startLng, mo.tilt])

    const pinKey = JSON.stringify(pins)
    useEffect(() => {
        if (!engine) return
        engine.setData(pins, p.arcs.mode, !!m.labels)
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [engine, pinKey, p.arcs.mode, m.labels])

    useEffect(() => {
        if (!engine) return
        engine.setSelected(selected)
    }, [engine, selected])

    useEffect(() => {
        if (!apiRef) return
        apiRef.current = engine ? { zoomBy: (f) => engine.zoomBy(f), reset: () => engine.reset() } : null
        return () => {
            apiRef.current = null
        }
    }, [engine, apiRef])

    // first frame after data, look and motion are in
    useEffect(() => {
        if (!engine || reduce === null) return
        engine.ready()
    }, [engine, reduce === null])

    return (
        <Frame p={p} pins={pins} live={true} ready={ready && !failed} rootRef={rootRef}>
            {mounted ? (
                <>
                    <canvas ref={canvasRef} className="adg-canvas" aria-hidden="true" />
                    <div ref={labelRef} className="adg-labels" aria-hidden="true" />
                </>
            ) : null}
        </Frame>
    )
}
