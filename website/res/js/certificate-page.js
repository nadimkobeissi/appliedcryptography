// DOM glue for the certificate verification page. The cryptography lives in the
// pure, separately-tested certificate-verify.js; this file only wires up the
// form, the QR/deep-link auto-verify, and result rendering.
import {
	verifyToken
} from './certificate-verify.js'
import {
	ISSUER_PUBKEY,
	ISSUER_FINGERPRINT,
	SEMESTERS,
	REVOKED
} from './certificate-data.js'
import {
	menuInit
} from './menu.js'

function b64urlToBytes(s) {
	s = s.replace(/-/g, '+').replace(/_/g, '/')
	const pad = s.length % 4
	if (pad) s += '='.repeat(4 - pad)
	const bin = atob(s)
	const out = new Uint8Array(bin.length)
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
	return out
}

const pubkeyRaw = b64urlToBytes(ISSUER_PUBKEY)

const REASONS = {
	'bad-signature': 'This token’s signature is not valid. It was not issued by this course, or it has been altered.',
	'malformed': 'This doesn’t look like a certificate token — check that you copied all of it.',
	'unsupported-version': 'This certificate uses a newer format than this page understands. Try refreshing the page.',
	'unknown-semester': 'This certificate refers to a semester this page doesn’t recognize.',
	'revoked': 'This certificate has been revoked and is no longer valid.',
	'crypto-unavailable': 'Your browser couldn’t run the required cryptography (Ed25519). Please use a current browser.',
}

const ESCAPES = {
	'&': '&amp;',
	'<': '&lt;',
	'>': '&gt;',
	'"': '&quot;',
	"'": '&#39;'
}

function esc(s) {
	return String(s).replace(/[&<>"']/g, (c) => ESCAPES[c])
}

function renderResult(el, result) {
	if (result.ok) {
		const {
			name,
			semester,
			grade,
			serialHex
		} = result.cert
		el.className = 'cert-result ok'
		el.innerHTML =
			`<h3><i class="icon ph-duotone ph-seal-check"></i>Verified</h3>` +
			`<p><strong class="cert-name">${esc(name)}</strong> completed ` +
			`<strong>Applied Cryptography (${esc(semester)})</strong> with a final grade of ` +
			`<strong>${esc(grade)}/100</strong>.</p>` +
			`<p class="cert-meta">Certificate #${esc(serialHex)}</p>`
	} else {
		el.className = 'cert-result err'
		el.innerHTML =
			`<h3><i class="icon ph-duotone ph-seal-warning"></i>Not verified</h3>` +
			`<p>${esc(REASONS[result.reason] || 'This certificate could not be verified.')}</p>`
	}
	el.hidden = false
}

function init() {
	menuInit()

	const fp = document.getElementById('cert-fp')
	if (fp) fp.textContent = ISSUER_FINGERPRINT

	const input = document.getElementById('cert-input')
	const button = document.getElementById('cert-verify')
	const result = document.getElementById('cert-result')

	async function run() {
		const token = input.value.trim()
		if (!token) {
			result.hidden = true
			return
		}
		button.disabled = true
		try {
			const verdict = await verifyToken(token, {
				pubkeyRaw,
				semesters: SEMESTERS,
				revoked: REVOKED
			})
			renderResult(result, verdict)
		} finally {
			button.disabled = false
		}
	}

	button.addEventListener('click', run)
	input.addEventListener('keydown', (e) => {
		if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
			e.preventDefault()
			run()
		}
	})

	// Auto-verify a QR / deep link: /certificate/#ACC1...
	if (location.hash.length > 1) {
		input.value = decodeURIComponent(location.hash.slice(1))
		run()
	}
}

if (document.readyState === 'loading') {
	document.addEventListener('DOMContentLoaded', init)
} else {
	init()
}