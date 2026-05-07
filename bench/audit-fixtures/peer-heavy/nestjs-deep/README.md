# nestjs-deep — peer-heavy compat fixture (deepest backend chain)

**Tests:** NestJS's decorator-based DI under both linker modes.

NestJS has one of the deepest peer-dep chains in mainstream backend
Node: `@nestjs/common` + `@nestjs/core` are tightly coupled through
peer deps; both depend on `reflect-metadata` for runtime metadata
reflection (which the decorator system uses) and `rxjs` for
Observable-based APIs. If hoisting nests a wrong version of
reflect-metadata or rxjs under one chain, DI silently breaks at
service-resolution time.

**Smoke test:** import the decorator + module APIs, register a
trivial service, and check that metadata reflection works. Plus a
quick rxjs round-trip to confirm the Observable instance is shared.
