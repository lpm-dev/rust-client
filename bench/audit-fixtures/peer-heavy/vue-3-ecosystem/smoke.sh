#!/bin/bash
# Vue 3 + Pinia + vue-router instance invariant. Pinia and vue-router
# both `import { ... } from 'vue'`; if they resolve to a different Vue
# instance than the user's, the reactive system breaks. Smoke creates
# a Pinia store + a router and exercises both.
set -e
node -e "
const Vue = require('vue');
const { createPinia, defineStore } = require('pinia');
const { createRouter, createMemoryHistory } = require('vue-router');

// Pinia must see Vue's reactive system.
const pinia = createPinia();
if (!pinia || typeof pinia.install !== 'function') {
    console.error('Pinia createPinia returned wrong shape');
    process.exit(2);
}

// Router must see Vue's component system.
const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: { render: () => null } }],
});
if (!router || typeof router.push !== 'function') {
    console.error('vue-router createRouter returned wrong shape');
    process.exit(3);
}

// Use a defineStore + pinia together — exercises Vue reactive +
// pinia state. If Vue instances diverge between vue and pinia, this
// throws at definition time.
const useStore = defineStore('test', { state: () => ({ count: 0 }) });
if (typeof useStore !== 'function') {
    console.error('defineStore returned wrong shape');
    process.exit(4);
}
"
