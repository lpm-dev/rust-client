# sharp-image — native compat fixture

**Tests:** lifecycle-script execution + native binding load + actual
native call. Sharp postinstall downloads platform-specific libvips
binary; binding layer dlopens it on first `require`. End-to-end smoke.

**Risk:** if hoisted layout puts sharp's bundled `node_modules` deps
in unexpected places, the binding loader's path heuristic may not
find the binary. Native modules are the highest-risk bucket because
they baked in npm/yarn-classic layout assumptions.
