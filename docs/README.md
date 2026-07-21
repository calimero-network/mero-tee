# Mero TEE Docs

The Mero TEE documentation site, built with [Astro Starlight](https://starlight.astro.build/)
and published to <https://calimero-network.github.io/mero-tee/>. Theme, favicon,
and the shared Calimero look are ported from
[calimero-network/core](https://github.com/calimero-network/core/tree/master/docs).

## Run it

```sh
cd docs
npm install
npm run dev      # http://localhost:4321/mero-tee/
npm run build    # static output in dist/
npm run check    # astro build + internal link check (what CI runs)
```

## Layout

Pages live in `src/content/docs/`, split into three tracks:

- **Understand** — what Mero TEE is: system overview, trust model, components, glossary.
- **How it works** — the runtime flows: attestation, key release, verification, policy.
- **Operate** — running it: config reference, release pipeline, runbooks, error handling.

The theme lives in `src/styles/theme.css`; the wordmark in `src/assets/logo-{light,dark}.svg`.
