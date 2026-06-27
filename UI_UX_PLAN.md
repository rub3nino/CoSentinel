# CoSentinel — UI/UX Redesign Plan (LIGHT MODE ONLY)

> Scope: `static/index.html` only. Single file, zero build, vanilla HTML/CSS/JS + `marked.js` CDN.
> Mode: **LIGHT ONLY** — no dark mode, no toggle. (Dark deferred — see Ponytail Cut.)
> Sources: `ui-ux-pro-max` skill (design system + UX rules) + `ponytail` (lazy senior dev).
> Status: **PLAN — awaiting review. No code until approved.**

---

## 0. Why this doc exists

Current `index.html` works (SSE, findings, report, PR) but reads "amateur" in places:
emojis used as icons, no focus rings, no reduced-motion, flat hero, no real breakpoints,
ad-hoc hex values. This plan fixes all of it against the skill's recommendations,
staying light-mode and minimal-effort where it doesn't hurt quality.

---

## 1. Skill verdict (ui-ux-pro-max)

Product classified as **ops / security developer tool**.

| Dimension | Recommendation |
|-----------|----------------|
| **Landing pattern** | Real-Time / Operations Landing → hero w/ live status · key metrics · how-it-works · CTA. Status colors green/amber/red. |
| **Style** | Hybrid: **Exaggerated Minimalism** (hero: oversized type, whitespace) + **Data-Dense Dashboard** (results: grid, compact rows, sticky headers, mono). |
| **Typography** | **Fira Sans** (UI) + **Fira Code** (data: evidence, file paths, IDs, counts, code blocks). Replaces Inter-only. |
| **Effects** | Hero `font-size: clamp(...)`, `font-weight 700–900`, `letter-spacing -0.04em`, massive whitespace. Findings: hover row highlight, tooltips. |
| **Avoid** | Excessive decoration, color-only indicators. |

### 1.1 Color tokens (light) — "document grey + scan blue"

| Token | Value | Use |
|-------|-------|-----|
| `--color-primary` | `#1E293B` | headings, primary surfaces, wordmark |
| `--color-on-primary` | `#FFFFFF` | text on primary |
| `--color-secondary` | `#334155` | secondary text |
| `--color-accent` | `#2563EB` | CTA, links, active, focus ring |
| `--color-background` | `#F8FAFC` | page bg |
| `--color-surface` | `#FFFFFF` | cards |
| `--color-foreground` | `#0F172A` | body text |
| `--color-muted` | `#64748B` | muted text (≥4.5:1 on white ✓) |
| `--color-border` | `#E4E5E7` | borders, dividers |
| `--color-destructive` | `#DC2626` | errors, CRITICAL |

Severity scale (light, all text ≥4.5:1 on their tint):

| Sev | Text | Tint bg | Border |
|-----|------|---------|--------|
| CRITICAL | `#DC2626` | `#FEF2F2` | `#FECACA` |
| HIGH | `#C2410C` | `#FFF7ED` | `#FED7AA` |
| MEDIUM | `#A16207` | `#FEFCE8` | `#FEF08A` | *(darkened from #ca8a04 — old failed AA)* |
| LOW | `#2563EB` | `#EFF6FF` | `#BFDBFE` |
| INFO | `#475569` | `#F1F5F9` | `#E2E8F0` |
| OK/clean | `#15803D` | `#F0FDF4` | `#BBF7D0` |

### 1.2 Spacing / radius / shadow / z (token scales)

- Spacing: `4 8 12 16 24 32 48 64 96` (px). 4/8 rhythm (`spacing-scale`).
- Radius: `--r-sm 6px · --r-md 8px · --r-lg 12px · --r-pill 999px`.
- Shadow (3 tiers only — `elevation-consistent`): `--sh-1` card rest, `--sh-2` card hover, `--sh-3` modal/sticky.
- Z-index scale: `nav 100 · sticky-header 40 · overlay 1000`.

### 1.3 Fonts

```html
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Fira+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
```
`--font-ui: 'Fira Sans'`, `--font-mono: 'Fira Code'`. `font-display: swap` (`font-loading`).

---

## 2. Phases (each = what / how / why-rule)

### Phase 0 — Foundation tokens
- **What:** `:root` block with all tokens above; swap font CDN; replace inline hex/radii/shadows with `var()`.
- **Why:** `color-semantic`, `spacing-scale`, `elevation-consistent`. One source of truth → later dark-mode = one block.

### Phase 1 — Iconography (CRITICAL)
- **What:** remove every emoji: `◈` wordmark, `🔧` PR, `📄`/`⬇` report, `⧉` copy, `→` CTA arrow, step dots, nav badge dot.
- **How:** inline Lucide SVG `<symbol>` defs once in `<body>`, reference via `<use>`. Icon set (~9): `shield`, `shield-check`, `download`, `copy`, `git-pull-request`, `check`, `alert-triangle`, `chevron-down`, `loader`, plus category icons `package`/`key`/`code`/`settings`.
- **Why:** `no-emoji-icons`, `icon-style-consistent`. Single stroke width (1.5px), sized via tokens (`icon-sm 16 · icon-md 20 · icon-lg 24`).

### Phase 2 — Accessibility (CRITICAL)
- Focus: `:focus-visible { outline:2px solid var(--color-accent); outline-offset:2px }` on every interactive el (`focus-states`).
- Reduced motion: `@media (prefers-reduced-motion: reduce)` disables pulse + transitions (`reduced-motion`).
- ARIA: progress list `role="status" aria-live="polite"`; error box `role="alert"`; finding card `aria-expanded`; path-copy + toasts `aria-live="polite"`, don't steal focus (`aria-live-errors`, `toast-accessibility`).
- Color-not-only: severity shown as **text label + icon**, not just tint (`color-not-only`).
- Contrast: MEDIUM text darkened (see 1.1); verify all pairs ≥4.5:1.
- Keyboard: convert clickable `.path-pill` span → real `<button>` so it's tabbable; `<details>`/`<summary>` already keyboard-native.

### Phase 3 — Hero (Exaggerated Minimalism)
- **What:** flat hero → statement hero w/ live status.
- **How:** H1 `clamp(2.5rem, 8vw, 5.5rem)`, weight 700–900, `letter-spacing:-0.04em`; vertical padding 96–120px; **live status chip** ("● scanner online · N models") populated from `/api/health` + `/api/models` on load; duplicate primary CTA in navbar (`primary-action`: one emphasized CTA, secondary subordinate).
- **Why:** Real-Time pattern = product + live status; style = oversized type, whitespace.

### Phase 4 — Scan card
- **What:** form polish + validation.
- **How:** visible `<label>` per field (`input-labels`); helper text under token ("only for private repos", `input-helper-text`); consistent 44px input height (`touch-friendly-input`); checkbox 20px hit area; CTA disabled = opacity .4 + `cursor:not-allowed` + `aria-disabled` (`disabled-states`); URL validate on blur → red border + message if host ≠ github.com (`inline-validation`, `error-clarity`).

### Phase 5 — Progress (SSE, keep 7 steps)
- **What:** richer real-time feedback.
- **How:** add "Step N of 7" counter (`multi-step-progress`) + elapsed timer in Fira Code; active = spinner SVG, done = green check w/ 200ms crossfade (`state-transition`, no snap); labels stay live from backend. Skeleton placeholder for report area during step 7.
- **Why:** `progress-indicators`, `loading-states`, `progressive-loading`.

### Phase 6 — Results = Data-Dense Dashboard (the payoff)
- **Risk score:** big Fira Code number + color band (red/orange/amber/green) + one-line justification beside it (parse report's "Overall Risk Score").
- **KPI row:** 4 cards (CRITICAL/HIGH/MEDIUM/LOW) — big count + label; **click filters** findings to that severity.
- **Findings:** dense list — sticky severity group headers, compact 36px rows, Fira Code `file:line` + IDs, hover row highlight (`row highlighting`), category icon per row. `<details>` expand stays.
- **Toolbar (conditional):** severity/category filter + text search + expand-all. *Build only if repos yield 20+ findings — see Ponytail.*
- **Why:** Data-Dense Dashboard style: max info, scannable. Findings = the product.

### Phase 7 — Report + PR
- Report: `h2` border-bottom, code blocks Fira Code on `--color-primary` bg, styled tables/lists; Copy + Download as icon+label buttons w/ focus + 2s "Copied" feedback (`success-feedback`).
- PR card: fixable count, pre-checked list, success → PR link w/ external-link icon + `aria-live`; token-missing → inline error not alert().

### Phase 8 — Micro-interactions (within motion budget)
- All hover/press transitions 150–300ms ease-out (`duration-timing`, `easing`).
- Button press `transform: scale(.98)` (`scale-feedback`); transform/opacity only (`transform-performance`).
- Finding rows stagger 30–50ms on render (`stagger-sequence`); card expand animates.
- **Everything gated by reduced-motion.**

### Phase 9 — Responsive (375 / 768 / 1024 / 1440)
- Hero clamp auto-scales; scan card 1-col mobile; KPI cards 2×2 mobile → 4-wide desktop; finding row stacks `file:line` under title <768px; nav badge wraps; container `max-width: 1100px`; `min-h-dvh` not `100vh`; no horizontal scroll (`mobile-first`, `breakpoint-consistency`, `horizontal-scroll`, `viewport-units`).

### Phase 10 — States
- Empty (0 findings): green "Repository clean" w/ `shield-check`, not blank.
- Error: restyle errBox as card + retry button (`error-recovery`).
- Loading: report skeleton during AI step.

---

## 3. Ponytail cut (deliberate skips)

| Skipped | Why / add-when |
|---------|----------------|
| **Dark mode** | Spec = light-only. Token foundation (Phase 0) makes it a future 1-block add. Add when explicitly requested. |
| **Filter/search toolbar** (Phase 6) | Medium-lazy. Worth it only at 20+ findings. Default: keep severity grouping. Add when real repos prove density. |
| **Report anchor nav / CSV export / findings chart** | Demo doesn't need. Add if judges want analytics. |
| **Icon library dependency** | No npm icon pkg — inline ~13 SVG symbols by hand. Stdlib of the web. |
| **CSS framework / build step** | Stays vanilla single-file + marked.js. No Tailwind, no bundler. |

**Lazy-but-not-careless (never cut):** focus rings, reduced-motion, contrast, input validation, ARIA — all kept; these are the "not lazy about" list.

---

## 4. Build order (impact ÷ effort)

1. **Phase 1 (emoji→SVG) + Phase 2 (a11y)** — cheap, kills amateur tells.
2. **Phase 0 tokens + Phase 3 hero + Phase 6 results** — the visual leap.
3. **Phase 5 progress + Phase 8 motion** — polish.
4. **Phase 4 / 7 / 9 / 10** — fill in.

Delivery: phase-by-phase edits to `index.html` (reviewable diffs), not one rewrite.

---

## 5. Acceptance checklist (verify before "done")

Visual
- [ ] Zero emoji as icons — all SVG, one icon family, 1.5px stroke
- [ ] Tokens only — no raw hex/radii/shadow in components
- [ ] Fira Sans UI + Fira Code for all data/code/IDs

Accessibility
- [ ] Visible `:focus-visible` ring on every interactive element
- [ ] `prefers-reduced-motion` respected (no pulse/transition when set)
- [ ] Severity = text + icon, never color alone
- [ ] All text pairs ≥4.5:1 (esp. MEDIUM, muted)
- [ ] Progress + toasts use `aria-live`; error uses `role="alert"`; no focus theft

Interaction
- [ ] Hover/press transitions 150–300ms ease-out, transform/opacity only
- [ ] Disabled CTA clearly non-interactive
- [ ] URL validates on blur with clear recovery message

Layout
- [ ] Tested 375 / 768 / 1024 / 1440 — no horizontal scroll
- [ ] 4/8 spacing rhythm; consistent `max-width`
- [ ] `min-h-dvh`, fixed nav reserves content padding

Function (no regression)
- [ ] SSE live labels still drive 7 steps
- [ ] Stats normalize SSE-uppercase + POST-lowercase
- [ ] Findings expand, path-copy, CVE links, fix code rendering intact
- [ ] PR + report copy/download intact

---

## 6. Open questions for review

1. Light-only confirmed? (plan assumes yes)
2. Build phase-by-phase (default) or one full rewrite?
3. Filter/search toolbar — build now or defer (Ponytail says defer)?
4. Keep ◈-style wordmark as a `shield` SVG, or keep a text wordmark "CoSentinel"?
