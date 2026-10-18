# LaunchDarkly session-replay cross-origin iframe hijack — runnable PoC

This repository reproduces a security issue in the LaunchDarkly browser
session-replay SDK (`@launchdarkly/session-replay@1.2.1`, built on
`@launchdarkly/o11y@1.3.0`).

## The issue in one paragraph

When the session-replay recorder initialises inside a **cross-origin iframe**,
it skips its own session setup and waits for a `postMessage` from the parent
page to tell it which project and session to record into. That message handler
checks only a public sentinel string (`'iframe parent ready'`); it never checks
the message origin. Any page that frames the victim app can therefore adopt the
recording: the victim user's session replay (DOM activity, logs, resources)
is exported to the backend keyed to a session ID chosen by the framing page.
This PoC reproduces that flow end to end in a real browser.

## Layout

- `run.js` — starts three local servers (victim app, attacker page, capture
  backend) and drives a headless Chromium through two scenarios.
- `public/victim/` — a normal app that initialises the real SDK from the
  published npm package (served from `node_modules`).
- `public/attacker/` — an unrelated page that frames the victim app and posts
  the handshake message. It uses no LaunchDarkly code.
- `.github/workflows/run-poc.yml` — runs the PoC on a clean Ubuntu runner.

## Run it

On GitHub Actions (no local setup):

1. Push this repository. The workflow runs automatically
   (or trigger it from the Actions tab).
2. Open the run log; the "Run PoC" step prints the full evidence.

Locally (Node 20+):

```bash
npm install
npx playwright install chromium
node run.js
```

## What you will see

```
[scenario 0] control (framed victim, no handshake message): 0 backend request(s)
...
Scenario 0 (control): backend requests = 0, attacker session present: false
Scenario 1 (attack):  backend requests = <n>, attacker session present: true, victim canary present in payloads: true

RESULT control (no handshake -> no export to attacker): true
RESULT hijack (victim export carries attacker session): true
RESULT victim content present in hijacked export:       true

VERDICT: VULNERABLE — the victim session replay was exported under the attacker-controlled session ID.
```

The run exits 0 when the hijack is observed.

## Safety notes

- Everything binds to `localhost`; the SDK's `backendUrl` option is pointed at
  the local capture server, so no traffic leaves the machine.
- No LaunchDarkly account, credential, sdkKey, or real project is used. The
  project and session identifiers in the PoC are local values.
- The run is deterministic: real Chromium, real published SDK bundle, no
  mocking of the vulnerable code path.

## Versions under test

- `@launchdarkly/session-replay` 1.2.1 (current npm release at the time of
  writing)
- `@launchdarkly/o11y` 1.3.0 (the browser client bundled inside it)

The published bundle contains the vulnerable code path (the SDK's UMD build
includes the `'iframe parent ready'` handler verbatim).
