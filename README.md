# gonstruct

**Plug-and-play backend components for Go.**

gonstruct is not a framework. It's a collection of composable, batteries-included
components that you wire into your own `net/http` server. Grab a whole feature
with one constructor when you want to move fast, or drop down to the individual
pieces and drive them yourself when you need control — the same way [jose](https://github.com/panva/jose)
lets you reach for just a JWT signer instead of a full auth stack.

Everything is built on the standard library. No magic, no hidden runtime, no
forced project layout.

## Design

- **Plug-and-play, not opinionated.** Components mount onto a plain
  `*http.ServeMux`. You stay in charge of routing, config, and lifecycle.
- **Low-level when you need it.** Every batteries-included entry point is
  assembled from smaller exported parts that are usable on their own.
- **Standard `http`, extended.** The [`httptools`](#httptools) package adds an
  error-returning handler type and a middleware-style error handler on top of
  `net/http` — nothing to relearn.
