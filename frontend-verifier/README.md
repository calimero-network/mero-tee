# Calimero frontend verifier

A browser extension that checks a Calimero app's page, file by file, against what the
app's attested node verified at install, so the person using the page does not have to
trust TLS, DNS or the operator.

Status: **first version**. It is not yet published to the Chrome Web Store or Firefox
Add-ons; load it unpacked (below).

## Why

An app's page decrypts and shows everything the signed-in person reads, and its own
JavaScript checks the node's attestation. So the person trusts whoever served that page.
On Calimero Cloud a page served by the node comes from the release's signed `.mpk`, but it
still reaches the browser over ordinary TLS: whoever can get a WebPKI certificate for the
app's origin (the operator, through the DNS zone it controls) could serve a different page
that skips the attestation check and reads the session. Nothing in the page can detect
that, because the page is the thing that was swapped. The check has to run outside it.

## What it does

For a page under a Calimero Cloud apps domain (`{label}.apps.calimero.network`, and
staging's), at `/{version}/...`:

1. Reads `/.well-known/calimero.json` on the page's origin for the package and the
   cluster's API nodes. This only says where to ask; it is trusted with nothing.
2. Attests a node with [mero-js](https://www.npmjs.com/package/@calimero-network/mero-js):
   the TDX quote and Intel's collateral, the Sigstore-signed mero-tee release (at least
   2.3.109, the image profile the Cloud trusts) and the transport key bound into the quote.
3. Asks that node, over the sealed channel, for the release's file list:
   `GET /packages/{package}/{version}/frontend` (core 1.0.0-rc.39 or later), every file with
   its SHA-256. The node computed them from the files it verified against the publisher's
   signature. Someone who swapped the page cannot answer this request: it would need the
   key attested inside the TEE.
4. Checks every file the page loads against that list, matching paths the way the node
   serves them (core's `app_host::resolve`: the exact path, the entry for a client route,
   leading segments dropped for a deep link).

| Browser | A changed or unlisted file |
| --- | --- |
| Firefox (128+) | Held and hashed before the page receives it, and never delivered. A page document is replaced by a warning. |
| Chrome | Detected after the page loaded it: the extension fetches the file again and compares. The page has already run it. Chrome's extension API does not give extensions the response body, so blocking is not possible without the debugger permission. |

The toolbar badge shows the verdict: **OK** (every file matched), **!** (a file did not
match or is not in the release: close the page and do not sign in), **?** (the page could
not be checked: no node passed attestation, or the cluster runs a core release before
1.0.0-rc.39). The popup shows the package, release, node and node image.

**Strict mode** (a checkbox in the popup, off by default) also blocks a page that cannot be
checked. Without it such a page is delivered with the **?** badge, so someone who can both
swap the page and keep every node from answering gets a warning shown rather than a block.

## What it does not cover

- A custom domain a package's manager registered: only the Calimero Cloud apps domains are
  watched.
- The release itself: the extension proves the page is the one the publisher signed, not
  that the publisher's code is honest.
- A node image that lies about the list. Attestation pins which image answers, and it is
  the same image the person already trusts with their data.

## Build, test, load

```bash
npm ci
npm run typecheck
npm test
npm run build          # dist/chrome and dist/firefox
```

- Chrome: `chrome://extensions`, Developer mode, Load unpacked, pick `dist/chrome`.
- Firefox: `about:debugging#/runtime/this-firefox`, Load Temporary Add-on, pick
  `dist/firefox/manifest.json`.

## Layout

- `src/core/site.ts`: which requests are app pages, which release file each one is, hashing.
- `src/core/listing.ts`: the well-known file, attestation through mero-js, the node's list.
- `src/core/verdict.ts`: a tab's state and verdict.
- `src/browser/background.ts`: the Firefox filter and the Chrome re-check (`install`);
  `entry.ts` wires it to the browser.
- `src/browser/popup.ts`, `static/`: the popup, the two manifests and the icon.

Design and the levels of frontend trust:
[mero-tee issue 666](https://github.com/calimero-network/mero-tee/issues/666), and
core's [Levels of frontend trust](https://calimero-network.github.io/core/protocol/applications/#levels-of-frontend-trust).
