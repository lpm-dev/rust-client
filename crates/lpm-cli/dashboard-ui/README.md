# LPM skills dashboard UI

`~/skill view` — a local inspector for agent skills, rebuilt from the
`SkillView.dc.html` Claude Design project.

React + TypeScript + Vite, handwritten CSS Modules over CSS custom properties.
The production build is embedded into the LPM binary. No Tailwind, component
library, router, or global state library is used.

## Commands

```
npm install
npm run dev        # dev server
npm run build      # typecheck + build the embedded Rust assets
npm test           # frontend unit and contract tests
npm run check:dist # rebuild and verify the committed Rust assets
npm run preview    # serve the built output
npm run typecheck
```

## Build constraints

The production bundle is static and same-origin by construction:

- `base: './'` — `dist/` runs from any path, no absolute URLs.
- `modulePreload.polyfill: false` — Vite emits **no inline `<script>`**.
- Zero external fonts or CDNs. Type is the system UI stack, declared once as
  `--font-sans`.
- **No inline style properties anywhere.** Every value the source design
  computed in JS is a CSS custom property or a CSS Module class, so the app
  runs under a CSP without `style-src 'unsafe-inline'`.
- Vite writes stable `assets/dashboard.js` and `assets/dashboard.css` names
  into `../src/commands/skills/dashboard/`. Cargo embeds those committed files
  and never invokes Node during a Rust build.

## Theming

The source design exposed two authored knobs. Both are data attributes on
`<html>` in `index.html`, resolved in `src/styles/tokens.css`:

```html
<html data-theme="light" data-accent="blue">
```

- `data-theme`: `light` | `dark`
- `data-accent`: `blue` (default) | `magenta` | `green` | `orange` | `violet`

## Backend seam

Every read and every action goes through one interface — `DashboardApi` in
[`src/api/types.ts`](src/api/types.ts).

```ts
interface DashboardApi {
  listSkills(signal?: AbortSignal): Promise<SkillsSnapshot>;
  getSkill(id: SkillId, signal?: AbortSignal): Promise<Skill | null>;
  revealSkill(id: SkillId): Promise<ActionResult>;
  previewAction(id: SkillId, action: SkillAction): Promise<ActionPreview>;
  applyAction(planId: string): Promise<ActionResult>;
}
```

`src/api/httpApi.ts` captures the launch token from the URL fragment, removes
it from the address bar, and sends authenticated same-origin requests to the
local Rust server. Inventory results carry lightweight list data. Selecting a
row fetches exact Markdown and bounded file details from
`GET /api/v1/skills/{id}`.

Reveal accepts only an inventory ID at the browser boundary. Managed
enable/disable/update/remove actions call preview first, render the returned
filesystem plan and diff in a review dialog, and send the opaque plan ID to
apply only after confirmation.

Copy-to-clipboard is genuinely wired, since it is a browser API rather than
backend behavior.

## Keyboard

| Key | Action |
| --- | --- |
| `/` | focus the filter field from anywhere outside a text field |
| `↑` `↓` `Home` `End` | move through the skill list |
| `↵` / `Space` | open the focused skill |
| `←` `→` | move between source tabs and detail tabs |

The list is a `listbox` with roving tabindex and `aria-selected`; both tab bars
are `tablist`s wired to their panels; status changes are announced through a
polite live region.

## Responsive

Above 900px the two panes sit side by side with the list fixed at 452px. Below
that they stack and the page scrolls as one document. Below 720px the stats
grid drops to two columns and the metadata table becomes single-column; below
640px the header sheds its secondary descriptors.

## Layout

```
src/
  api/          DashboardApi interface + authenticated HTTP transport
  lib/          markdown parsing, file tree, filter/sort, view-model helpers
  components/   presentational components, one CSS Module each
  styles/       tokens.css (light/dark palettes + accents), global.css
```
