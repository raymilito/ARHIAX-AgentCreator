// Package merkle implements the append-only hash chain that gives the
// evidence store its tamper-evidence property.
//
// # Threat model
//
// We protect against three concrete attacks:
//
//  1. Silent record modification.
//     An attacker with write access to the JSONL file edits a single
//     record (e.g. flips an "allow":false to "allow":true) and saves
//     the file. With the chain in place, this breaks the next record's
//     prev_hash check and is detectable by a single Verify pass.
//
//  2. Silent record deletion.
//     An attacker removes a record from the middle of the file. The
//     next record's prev_hash no longer matches the new predecessor's
//     hash, so this is also detectable.
//
//  3. Silent record reordering.
//     An attacker swaps two records. The hashes no longer chain
//     correctly, so this is also detectable.
//
// What we explicitly do NOT protect against:
//
//   - Truncation of the tail of the file. An attacker who deletes the
//     last N records leaves a self-consistent chain of length len-N.
//     Defense against this requires either an external witness (e.g.
//     periodic publication of the head hash to a transparency log) or
//     a signed checkpoint, neither of which are in v1.0.0 scope.
//   - Total file replacement. Same caveat: needs an external root of
//     trust.
//   - Compromise of the running process before it writes a record.
//     A malicious or buggy gateway can simply choose not to send the
//     record. The store cannot record what it never received.
//
// These limitations are honest and standard for any append-only log
// without an external anchor. The roadmap for v1.1+ includes signed
// checkpoints and Rekor-style transparency log integration to close
// the truncation and replacement gaps.
//
// # Hash function and canonicalization
//
// We use SHA-256 (FIPS 180-4) for the chain hash. The input to the
// hash for record N is:
//
//	prev_hash_bytes (32 bytes, raw, NOT hex)
//	|| canonical_json(record_payload) (UTF-8, no trailing newline)
//
// Concatenation is by direct byte append, not by string formatting,
// to eliminate any ambiguity about separators or escaping.
//
// canonical_json is a stable serialization with sorted object keys at
// every level. We do NOT use Go's encoding/json directly for hashing
// because Go's marshaller does sort map keys but does NOT sort struct
// field order in any guaranteed way for nested any/interface values.
// Since the gateway sends Subject/Action/Resource/Context as opaque
// JSON pass-through, we re-canonicalize on the store side to ensure
// deterministic hashing across language implementations.
//
// The first record (genesis) uses prev_hash = 32 zero bytes.
//
// # Length extension
//
// SHA-256 is vulnerable to length-extension attacks when used as a
// MAC (i.e. H(secret || message)). We are NOT using it as a MAC: the
// input contains no secret. The hash is purely an integrity link.
// If a future version adds a per-store HMAC for record signing, it
// MUST use HMAC-SHA256, not raw SHA-256.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// HashSize is the byte length of a SHA-256 digest.
const HashSize = sha256.Size

// ZeroHash is the prev_hash used for the genesis (first) record.
// Defining it as a package var (rather than a literal) makes intent
// explicit at every callsite and lets tests reference the same value.
var ZeroHash = make([]byte, HashSize)

// ComputeHash returns the chain hash of a record given its predecessor's
// hash and the canonical JSON of the record payload.
//
// The payload is the JSON marshaling of the user-supplied fields ONLY
// (subject/action/resource/context/decision/reasons/obligations/...).
// It MUST NOT include the id, timestamp, prev_hash, or hash fields,
// because those are assigned by the store and including them would
// create a circular dependency in the hash computation.
//
// prevHash MUST be exactly HashSize bytes. Use ZeroHash for the genesis
// record. The function returns an error rather than panicking so that
// callers loading a corrupted file get a structured error, not a crash.
func ComputeHash(prevHash []byte, canonicalPayload []byte) ([]byte, error) {
	if len(prevHash) != HashSize {
		return nil, fmt.Errorf("merkle: prev_hash must be %d bytes, got %d", HashSize, len(prevHash))
	}
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonicalPayload)
	return h.Sum(nil), nil
}

// HashHex is a convenience wrapper that returns the hex-encoded hash.
// Hex is the on-the-wire format used in HTTP responses and the JSONL
// file. The raw byte form is only used in chain computation.
func HashHex(prevHashHex string, canonicalPayload []byte) (string, error) {
	prev, err := DecodeHash(prevHashHex)
	if err != nil {
		return "", err
	}
	h, err := ComputeHash(prev, canonicalPayload)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h), nil
}

// EncodeHash converts a raw 32-byte hash to its hex string form.
func EncodeHash(raw []byte) string {
	return hex.EncodeToString(raw)
}

// DecodeHash converts a hex-encoded hash back to its 32-byte form.
// Returns an error on bad hex or wrong length.
func DecodeHash(s string) ([]byte, error) {
	// Special case: the genesis prev_hash is conventionally written
	// as 64 zero hex chars, but we also accept the empty string as
	// shorthand for ZeroHash to make manual file inspection easier.
	if s == "" {
		out := make([]byte, HashSize)
		return out, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("merkle: decode hash: %w", err)
	}
	if len(b) != HashSize {
		return nil, fmt.Errorf("merkle: hash must be %d bytes, got %d", HashSize, len(b))
	}
	return b, nil
}

// CanonicalJSON serializes v as JSON with object keys sorted recursively
// at every nesting level. This produces a deterministic byte sequence
// that two different implementations (Go, Python, Rust) will agree on,
// which is the requirement for cross-language hash verification.
//
// The implementation marshals once with encoding/json, decodes into
// any, then re-encodes with sorted keys. It is O(n) in record size
// and adds ~5-10us per record at typical evidence sizes (sub-kilobyte).
// At our expected QPS (under 1k decisions/sec for v1.0.0), this is
// well below the headroom of any disk fsync.
func CanonicalJSON(v any) ([]byte, error) {
	// First pass: standard marshal to get the data into a generic shape.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("merkle: marshal: %w", err)
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // preserve int vs float exactness
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("merkle: decode for canonicalization: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical recursively serializes v to w with sorted object keys.
// The output uses no whitespace. Strings are escaped using Go's standard
// JSON string encoding so non-ASCII bytes are handled identically to
// encoding/json's default.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		// Use encoding/json for string escaping to match wire format.
		s, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(s)
	case json.Number:
		buf.WriteString(string(x))
	case float64:
		// Should be unreachable because we use UseNumber, but kept as
		// a defensive branch in case a caller passes a typed struct.
		s, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(s)
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			ks, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(ks)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		// Fallback: marshal whatever it is and let encoding/json decide.
		// This branch handles typed structs passed without going through
		// the generic decode pass — useful for unit tests.
		s, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(s)
	}
	return nil
}

// VerifyChain checks that a sequence of (prev_hash, payload, hash) triples
// forms a valid chain starting from ZeroHash. Returns the index of the
// first broken record, or -1 if the chain is valid.
//
// This is the function an auditor (or `arhiax-evidence verify` CLI in a
// future release) calls to prove the file has not been tampered with.
type Triple struct {
	PrevHashHex      string
	CanonicalPayload []byte
	HashHex          string
}

func VerifyChain(records []Triple) (int, error) {
	expectedPrev := ZeroHash
	for i, r := range records {
		gotPrev, err := DecodeHash(r.PrevHashHex)
		if err != nil {
			return i, fmt.Errorf("record %d: prev_hash: %w", i, err)
		}
		if !bytes.Equal(gotPrev, expectedPrev) {
			return i, fmt.Errorf("record %d: prev_hash mismatch (chain broken)", i)
		}
		computed, err := ComputeHash(gotPrev, r.CanonicalPayload)
		if err != nil {
			return i, fmt.Errorf("record %d: compute hash: %w", i, err)
		}
		stated, err := DecodeHash(r.HashHex)
		if err != nil {
			return i, fmt.Errorf("record %d: hash decode: %w", i, err)
		}
		if !bytes.Equal(computed, stated) {
			return i, fmt.Errorf("record %d: hash mismatch (record tampered)", i)
		}
		expectedPrev = stated
	}
	return -1, nil
}
