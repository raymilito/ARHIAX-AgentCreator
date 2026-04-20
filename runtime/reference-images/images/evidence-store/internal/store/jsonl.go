// Package store implements the on-disk evidence ledger.
//
// The v1.0.0 driver is "jsonl": newline-delimited JSON, one record per
// line, append-only, with a Merkle hash chain linking each record to its
// predecessor. The package exposes an interface (Store) so that a future
// SQL driver can drop in without touching the HTTP server.
//
// # Durability model
//
//   - Every Append() call holds a writer mutex (single-writer semantics).
//   - The record is serialized to JSON, written via a single write() to
//     reduce torn-write risk, and then fsync'd before the call returns.
//   - On startup, the existing file is replayed line by line. The replay
//     verifies the chain as it goes; on the first broken record, OpenJSONL
//     returns an error and refuses to continue. Operators must inspect
//     and recover manually — never silently truncate.
//
// # Crash recovery
//
// If the process crashes mid-write, the file may end with a partial
// (unparseable) line. On the next OpenJSONL the replay catches the parse
// error at that line and returns it; the operator can then either
// truncate the partial line manually, or restore from a backup. We
// deliberately do NOT auto-truncate — silent data loss in an audit
// system is worse than loud failure.
//
// # In-memory state
//
// We keep a tiny index of (id → file offset) in memory so that GET by
// id is O(1) seek + read instead of full file scan. For v1.0.0 quick-
// start volumes (sub-million records) the memory cost is negligible
// (~80 bytes per record × 1M = 80 MB worst case). For larger volumes
// the chart's roadmap moves to the SQL driver where the index lives
// in the database.
package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arhiax/arhiax/evidence-store/internal/merkle"
)

// Record is the on-disk shape. Field order in this struct is irrelevant
// because we always serialize through merkle.CanonicalJSON for the hash
// computation, but we use json struct tags to keep the wire format
// readable for humans cat-ing the file.
type Record struct {
	// Assigned by the store on append. Clients MUST NOT set these.
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"` // RFC 3339 nano, UTC
	PrevHash  string `json:"prev_hash"` // hex SHA-256
	Hash      string `json:"hash"`      // hex SHA-256

	// Identity of the producer.
	PodNamespace string `json:"pod_namespace"`
	PodName      string `json:"pod_name"`

	// Decision content. Pass-through from the gateway.
	Subject     any      `json:"subject"`
	Action      any      `json:"action"`
	Resource    any      `json:"resource"`
	Context     any      `json:"context"`
	Decision    bool     `json:"decision"`
	Reasons     []string `json:"reasons,omitempty"`
	Obligations []any    `json:"obligations,omitempty"`
}

// hashablePayload is the subset of Record that goes into the chain hash.
// It explicitly EXCLUDES id, timestamp, prev_hash, and hash because those
// are computed by the store and including them would make the hash
// circular. It also excludes pod_namespace/pod_name on purpose: the
// pod identity is metadata, not content, and we want chain verification
// to be stable across pod restarts (which would otherwise change the
// hash for identical decisions).
type hashablePayload struct {
	Subject     any      `json:"subject"`
	Action      any      `json:"action"`
	Resource    any      `json:"resource"`
	Context     any      `json:"context"`
	Decision    bool     `json:"decision"`
	Reasons     []string `json:"reasons,omitempty"`
	Obligations []any    `json:"obligations,omitempty"`
}

// Store is the interface the HTTP server depends on. Concrete drivers
// (jsonl in v1.0.0, sql in v1.1) implement it.
type Store interface {
	Append(ctx context.Context, in Record) (Record, error)
	GetByID(ctx context.Context, id string) (Record, bool, error)
	Tail(ctx context.Context, limit int) ([]Record, error)
	Count() uint64
	HeadHash() string
	Close() error
}

// JSONLStore is the v1.0.0 driver.
type JSONLStore struct {
	path   string
	logger *slog.Logger

	// Append mutex: only one writer at a time. Reads happen under a
	// separate RLock on the index map.
	writeMu sync.Mutex
	file    *os.File // open in append mode

	// Index: id → byte offset of the JSONL line for that record.
	indexMu sync.RWMutex
	index   map[string]int64

	// Head state: hash of the last record (or ZeroHash hex if empty).
	headHashHex string
	count       uint64 // atomic

	// Sequence counter for monotonic ID generation. Combined with the
	// process start time so IDs are sortable and globally unique even
	// across restarts (the start time prefix changes on every boot).
	startNanos int64
	seq        uint64 // atomic
}

// OpenJSONL opens (or creates) the JSONL file at path and replays it
// to rebuild the index and head hash. Returns an error if the chain is
// broken or any line is unparseable.
func OpenJSONL(path string, logger *slog.Logger) (*JSONLStore, error) {
	// Open with O_CREATE so a fresh deployment works without manual
	// file creation. 0o640 keeps the file readable by the running user
	// and its group only — operators can chmod looser if they want.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open jsonl: %w", err)
	}

	s := &JSONLStore{
		path:        path,
		logger:      logger.With(slog.String("subcomponent", "jsonl_store")),
		file:        f,
		index:       make(map[string]int64),
		headHashHex: merkle.EncodeHash(merkle.ZeroHash),
		startNanos:  time.Now().UnixNano(),
	}

	if err := s.replay(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return s, nil
}

// replay reads the file from the beginning, validates the chain, and
// rebuilds the index. Called once at OpenJSONL.
func (s *JSONLStore) replay() error {
	// Open a separate read handle so the bufio.Scanner does not interfere
	// with the append-mode file descriptor's offset.
	rf, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("open for replay: %w", err)
	}
	defer rf.Close()

	br := bufio.NewReaderSize(rf, 64*1024)
	var offset int64 = 0
	var lineNum int = 0
	expectedPrev := merkle.EncodeHash(merkle.ZeroHash)

	for {
		// Read one line. We use ReadBytes('\n') instead of bufio.Scanner
		// because Scanner has a 64KB default token limit that some legit
		// records (with large obligation lists) could exceed.
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && errors.Is(err, io.EOF) {
			break
		}
		lineNum++
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("replay: read line %d: %w", lineNum, err)
		}
		// A trailing partial line (no newline) at EOF is treated as
		// torn write and surfaces as an error so the operator notices.
		if !endsWithNewline(line) {
			return fmt.Errorf("replay: line %d at offset %d is not newline-terminated (likely torn write or partial flush)", lineNum, offset)
		}

		var rec Record
		if jerr := json.Unmarshal(trimNewline(line), &rec); jerr != nil {
			return fmt.Errorf("replay: line %d unparseable: %w", lineNum, jerr)
		}

		// Verify prev_hash links to the previous record.
		if rec.PrevHash != expectedPrev {
			return fmt.Errorf("replay: line %d prev_hash mismatch (chain broken)", lineNum)
		}
		// Recompute and verify this record's hash.
		payload := hashablePayload{
			Subject: rec.Subject, Action: rec.Action, Resource: rec.Resource,
			Context: rec.Context, Decision: rec.Decision,
			Reasons: rec.Reasons, Obligations: rec.Obligations,
		}
		canonical, cerr := merkle.CanonicalJSON(payload)
		if cerr != nil {
			return fmt.Errorf("replay: line %d canonicalize: %w", lineNum, cerr)
		}
		gotHash, herr := merkle.HashHex(rec.PrevHash, canonical)
		if herr != nil {
			return fmt.Errorf("replay: line %d hash compute: %w", lineNum, herr)
		}
		if gotHash != rec.Hash {
			return fmt.Errorf("replay: line %d hash mismatch (record tampered)", lineNum)
		}

		// Index this record by id.
		s.indexMu.Lock()
		s.index[rec.ID] = offset
		s.indexMu.Unlock()
		expectedPrev = rec.Hash
		offset += int64(len(line))
		atomic.AddUint64(&s.count, 1)
	}
	s.headHashHex = expectedPrev
	s.logger.Info("replay complete",
		slog.Int("lines", lineNum),
		slog.String("head_hash", s.headHashHex))
	return nil
}

func endsWithNewline(b []byte) bool {
	return len(b) > 0 && b[len(b)-1] == '\n'
}

func trimNewline(b []byte) []byte {
	if endsWithNewline(b) {
		return b[:len(b)-1]
	}
	return b
}

// Append serializes, hashes, writes, and fsyncs a record. Returns the
// fully-populated Record (with id, timestamp, prev_hash, hash) on success.
func (s *JSONLStore) Append(ctx context.Context, in Record) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Build the canonical payload first; if this fails, the chain is
	// untouched.
	payload := hashablePayload{
		Subject:     in.Subject,
		Action:      in.Action,
		Resource:    in.Resource,
		Context:     in.Context,
		Decision:    in.Decision,
		Reasons:     in.Reasons,
		Obligations: in.Obligations,
	}
	canonical, err := merkle.CanonicalJSON(payload)
	if err != nil {
		return Record{}, fmt.Errorf("canonicalize: %w", err)
	}

	prev := s.headHashHex
	hash, err := merkle.HashHex(prev, canonical)
	if err != nil {
		return Record{}, fmt.Errorf("hash: %w", err)
	}

	out := Record{
		ID:           s.nextID(),
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PrevHash:     prev,
		Hash:         hash,
		PodNamespace: in.PodNamespace,
		PodName:      in.PodName,
		Subject:      in.Subject,
		Action:       in.Action,
		Resource:     in.Resource,
		Context:      in.Context,
		Decision:     in.Decision,
		Reasons:      in.Reasons,
		Obligations:  in.Obligations,
	}

	line, err := json.Marshal(out)
	if err != nil {
		return Record{}, fmt.Errorf("marshal: %w", err)
	}
	line = append(line, '\n')

	// Capture current EOF offset BEFORE writing so the index points at
	// the start of this line, not the end.
	offset, err := s.file.Seek(0, io.SeekEnd)
	if err != nil {
		return Record{}, fmt.Errorf("seek end: %w", err)
	}
	if _, err := s.file.Write(line); err != nil {
		return Record{}, fmt.Errorf("write: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return Record{}, fmt.Errorf("fsync: %w", err)
	}

	// Commit in-memory state ONLY after the fsync succeeds. If the
	// fsync fails, the chain head stays where it was and the next
	// append will overwrite or extend correctly.
	s.indexMu.Lock()
	s.index[out.ID] = offset
	s.indexMu.Unlock()
	s.headHashHex = hash
	atomic.AddUint64(&s.count, 1)

	return out, nil
}

// nextID generates a monotonic id of the form "ev-<startNanos>-<seq>".
// Sortable, globally unique across pod restarts (assuming a clock that
// does not jump backward), and short enough for log greppability.
func (s *JSONLStore) nextID() string {
	n := atomic.AddUint64(&s.seq, 1)
	return fmt.Sprintf("ev-%d-%d", s.startNanos, n)
}

// GetByID looks up a record by id. Returns (Record, false, nil) if not
// found and (Record, false, err) only on real I/O errors.
func (s *JSONLStore) GetByID(ctx context.Context, id string) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	s.indexMu.RLock()
	offset, ok := s.index[id]
	s.indexMu.RUnlock()
	if !ok {
		return Record{}, false, nil
	}

	// Open a fresh handle to avoid contending with the writer's append
	// position. Cheap on Linux: open() of an existing file is microseconds.
	rf, err := os.Open(s.path)
	if err != nil {
		return Record{}, false, fmt.Errorf("open for read: %w", err)
	}
	defer rf.Close()
	if _, err := rf.Seek(offset, io.SeekStart); err != nil {
		return Record{}, false, fmt.Errorf("seek: %w", err)
	}
	br := bufio.NewReader(rf)
	line, err := br.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return Record{}, false, fmt.Errorf("read line: %w", err)
	}

	var rec Record
	if jerr := json.Unmarshal(trimNewline(line), &rec); jerr != nil {
		return Record{}, false, fmt.Errorf("unmarshal: %w", jerr)
	}
	return rec, true, nil
}

// Tail returns the last `limit` records in chronological (file) order.
// Implementation is naive (full scan from start) because v1.0.0 expected
// volumes are small. For larger volumes the SQL driver in v1.1 will
// implement this with an index. Documented as a known performance
// limitation, not a bug.
func (s *JSONLStore) Tail(ctx context.Context, limit int) ([]Record, error) {
	if limit <= 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rf, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("open for tail: %w", err)
	}
	defer rf.Close()

	// Ring buffer of the last `limit` records. O(N) time, O(limit) space.
	ring := make([]Record, 0, limit)
	br := bufio.NewReaderSize(rf, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && errors.Is(err, io.EOF) {
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("tail read: %w", err)
		}
		if !endsWithNewline(line) {
			break // partial trailing line — ignore for tail purposes
		}
		var rec Record
		if jerr := json.Unmarshal(trimNewline(line), &rec); jerr != nil {
			return nil, fmt.Errorf("tail unmarshal: %w", jerr)
		}
		if len(ring) == limit {
			ring = ring[1:]
		}
		ring = append(ring, rec)
	}
	return ring, nil
}

// Count returns the number of records in the chain.
func (s *JSONLStore) Count() uint64 {
	return atomic.LoadUint64(&s.count)
}

// HeadHash returns the hex SHA-256 of the most recent record (or the
// genesis ZeroHash if the chain is empty).
func (s *JSONLStore) HeadHash() string {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.headHashHex
}

// Close fsyncs and closes the underlying file. After Close, Append will
// panic on the file write — callers MUST shut down the HTTP listener
// before calling Close. main.go enforces this ordering.
func (s *JSONLStore) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.file == nil {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		_ = s.file.Close()
		s.file = nil
		return fmt.Errorf("close fsync: %w", err)
	}
	err := s.file.Close()
	s.file = nil
	return err
}
