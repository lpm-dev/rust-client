# vue-3-ecosystem — peer-heavy compat fixture (Vue ecosystem)

**Tests:** Vue 3's "single Vue instance" invariant under both linker
modes. Pinia and vue-router both declare `vue` as a peer; if the
hoisting / isolation puts a different Vue instance behind one of
them, Vue's reactive system breaks — same risk shape as React's hooks
dispatcher, just on the other major framework.

**Smoke test:** create a Pinia instance, a router with a memory
history, and a store via `defineStore`. Each touches a different
Vue-internals surface. A multi-instance bug fails loudly at the call
to `defineStore` (Pinia checks Vue's reactive identity).

Companion to [`peer-heavy/react-ssr`](../react-ssr) — symmetric
coverage so the audit doesn't depend on a single framework's quirks.
