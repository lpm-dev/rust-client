# vite-react — peer-heavy compat fixture

**Tests:** Vite + @vitejs/plugin-react peer chain under both layouts.

The plugin lists `vite` as a peer and (transitively via Babel) needs
React. Multi-step peer resolution is more sensitive to layout than the
two-package react-ssr fixture.

**Smoke test:** runs `vite --version` (CLI bin resolves) and instantiates
the React plugin (validates the plugin's own deps load cleanly).
