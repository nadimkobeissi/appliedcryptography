export const ISSUER_PUBKEY = 'L5KIS06wLoziPyIr79Ttn4FnNBdWB_jF-AO_NE9pIOI'
export const ISSUER_FINGERPRINT = '209ae7e9ebbb6e3b0b45a8b1d58b5067d2fbf8918e19d74f154aaf5865f03b73'

// To add a semester: add its enum byte → label below. It must match the -semester value used when signing.
export const SEMESTERS = {
	0: 'Fall 2025',
	1: 'Summer 2026',
}

// To revoke a certificate: add its serial (the 16-hex "serial" column from the issuer's output) to REVOKED.
export const REVOKED = []