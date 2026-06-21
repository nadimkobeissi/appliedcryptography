// Pure, DOM-free verifier for Applied Cryptography completion certificates.
// Runs unchanged in the browser and under Node (uses the web-standard
// crypto.subtle / atob / TextDecoder globals).
//
//   token   = "ACC1." + base64url( payload || signature[64] )
//   payload = ver(1) || sem(1) || grade(1) || serial(8) || name(UTF-8)
//
// See docs/superpowers/specs/2026-06-21-certificate-verification-design.md.

const PREFIX = 'ACC1.'
const SIG_LEN = 64
const HEADER_LEN = 11 // ver(1) + sem(1) + grade(1) + serial(8)
const SCHEMA_VERSION = 2

function b64urlToBytes(s) {
	s = s.replace(/-/g, '+').replace(/_/g, '/')
	const pad = s.length % 4
	if (pad) s += '='.repeat(4 - pad)
	const bin = atob(s) // throws on invalid base64
	const out = new Uint8Array(bin.length)
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
	return out
}

function toHex(bytes) {
	let h = ''
	for (const b of bytes) h += b.toString(16).padStart(2, '0')
	return h
}

/**
 * Verify a certificate token against the issuer's Ed25519 public key.
 *
 * @param {string} token
 * @param {{pubkeyRaw: Uint8Array, semesters: Record<string,string>, revoked: string[]}} opts
 * @returns {Promise<{ok: true, cert: {name: string, semester: string, grade: number, serialHex: string}}
 *                  | {ok: false, reason: string}>}
 *   reason ∈ malformed | bad-signature | unsupported-version | unknown-semester | revoked | crypto-unavailable
 */
export async function verifyToken(token, {
	pubkeyRaw,
	semesters,
	revoked
}) {
	if (typeof token !== 'string') return {
		ok: false,
		reason: 'malformed'
	}
	const trimmed = token.trim()
	if (!trimmed.startsWith(PREFIX)) return {
		ok: false,
		reason: 'malformed'
	}

	let blob
	try {
		blob = b64urlToBytes(trimmed.slice(PREFIX.length))
	} catch {
		return {
			ok: false,
			reason: 'malformed'
		}
	}
	if (blob.length < HEADER_LEN + SIG_LEN) return {
		ok: false,
		reason: 'malformed'
	}

	const payload = blob.subarray(0, blob.length - SIG_LEN)
	const signature = blob.subarray(blob.length - SIG_LEN)

	// Verify the signature over the exact transmitted payload bytes.
	let valid
	try {
		const key = await crypto.subtle.importKey('raw', pubkeyRaw, {
			name: 'Ed25519'
		}, false, ['verify'])
		valid = await crypto.subtle.verify({
			name: 'Ed25519'
		}, key, signature, payload)
	} catch {
		return {
			ok: false,
			reason: 'crypto-unavailable'
		}
	}
	if (!valid) return {
		ok: false,
		reason: 'bad-signature'
	}

	// Only parse for display once the signature is trusted.
	if (payload[0] !== SCHEMA_VERSION) return {
		ok: false,
		reason: 'unsupported-version'
	}

	const semester = semesters[payload[1]]
	if (semester === undefined) return {
		ok: false,
		reason: 'unknown-semester'
	}

	const grade = payload[2]

	const serialHex = toHex(payload.subarray(3, HEADER_LEN))
	if (revoked.includes(serialHex)) return {
		ok: false,
		reason: 'revoked'
	}

	const name = new TextDecoder('utf-8').decode(payload.subarray(HEADER_LEN))
	return {
		ok: true,
		cert: {
			name,
			semester,
			grade,
			serialHex
		}
	}
}