package ledger

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit_CompactionCrashWindowMustRecover(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.json")
	l := New()
	var journal bytes.Buffer
	for i := 0; i < compactEvery; i++ {
		e := l.Append("entry")
		if err := json.NewEncoder(&journal).Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := l.Dump()
	if err != nil {
		t.Fatal(err)
	}
	// Exact disk state after snapshot rename but before journal truncation.
	// Both files are valid and contain the same committed prefix.
	if err := os.WriteFile(path, snapshot, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath(path), journal.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("valid overlapping snapshot/journal after compaction crash rejected: %v", err)
	}
	if got.Len() != compactEvery {
		t.Fatalf("recovered entries=%d want=%d", got.Len(), compactEvery)
	}
}

func TestAudit_CompletedCorruptTailMustNotBeSilentlyDropped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.json")
	l := New()
	for i := 0; i < 3; i++ {
		l.Append("committed entry")
	}
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	jp := journalPath(path)
	b, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	lines[2] = `{invalid complete record}`
	corrupt := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(jp, []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := Load(path)
	if err != nil {
		return
	} // Desired: refuse a newline-terminated corrupt record.
	remaining, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	lostLen := recovered.Len()
	recovered.Append("new entry")
	if err := recovered.Save(path); err != nil {
		t.Fatal(err)
	}
	_, secondErr := Load(path)
	t.Errorf("completed corrupt final record silently dropped: recovered=%d of 3; bad bytes retained=%t; after appending next entry restart=%v",
		lostLen, string(remaining) == corrupt, secondErr)
}
