package main

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HerodotusTree/grove-network/identity"
	"github.com/HerodotusTree/grove-network/ledger"
	"github.com/HerodotusTree/grove-network/vault"
)

// These tests assert safe behavior. FAIL means the stated counterexample
// reproduced. All filesystem operations use t.TempDir; only the SSRF test
// opens a listener, and that listener is a disposable loopback test server.
func auditServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	return &server{v: vault.New(ledger.New()), nonces: map[string]uint64{},
		dataDir: dir, chainPath: filepath.Join(dir, "chain.json"),
		noncePath: filepath.Join(dir, "nonces.json"), started: time.Now()}
}

func auditKey(t *testing.T) (string, string) {
	t.Helper()
	priv, pub, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func auditSigned(t *testing.T, op, priv, pub string, amount int64, nonce uint64) []byte {
	t.Helper()
	sig, err := identity.Sign(priv, identity.Payload(op, pub, amount, nonce))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(signedReq{Account: pub, Amount: amount, Nonce: nonce, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func auditPost(s *server, path string, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	switch path {
	case "/deposit":
		s.handleDeposit(w, r)
	case "/redeem":
		s.handleRedeem(w, r)
	case "/tip":
		s.handleTip(w, r)
	case "/peers":
		s.handlePeers(w, r)
	case "/sync":
		s.handleSync(w, r)
	default:
		panic("unknown test route")
	}
	return w
}

func auditStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("setup: status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
}

func auditRestart(s *server) (*server, error) {
	next := &server{dataDir: s.dataDir, chainPath: s.chainPath, noncePath: s.noncePath, started: time.Now()}
	v, err := next.loadOrNew()
	if err != nil {
		return nil, err
	}
	nonces, err := loadNonces(next.noncePath)
	if err != nil {
		return nil, err
	}
	next.v, next.nonces = v, nonces
	return next, nil
}

type auditTransport func(*http.Request) (*http.Response, error)

func (f auditTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func auditSyncEntries(t *testing.T, s *server, entries []ledger.Entry) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	previous := http.DefaultTransport
	defer func() { http.DefaultTransport = previous }()
	http.DefaultTransport = auditTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "http://audit-peer.invalid/ledger" {
			t.Fatalf("unexpected request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header),
			Body: io.NopCloser(bytes.NewReader(data))}, nil
	})
	auditStatus(t, auditPost(s, "/peers", []byte(`{"url":"http://audit-peer.invalid"}`)), 200)
	return auditPost(s, "/sync", nil)
}

func TestAudit_RedeemRequiresOwnership(t *testing.T) {
	s := auditServer(t)
	alicePriv, alice := auditKey(t)
	bobPriv, bob := auditKey(t)
	auditStatus(t, auditPost(s, "/deposit", auditSigned(t, "deposit", alicePriv, alice, 100, 1)), 200)
	bobResponse := auditPost(s, "/redeem", auditSigned(t, "redeem", bobPriv, bob, 100, 1))
	aliceResponse := auditPost(s, "/redeem", auditSigned(t, "redeem", alicePriv, alice, 100, 2))
	if bobResponse.Code == 200 {
		t.Errorf("fresh Bob with no deposits redeemed Alice's 100: Bob HTTP %d %s; Alice HTTP %d %s",
			bobResponse.Code, bobResponse.Body.String(), aliceResponse.Code, aliceResponse.Body.String())
	}
}

func TestAudit_ReplayAfterSync(t *testing.T) {
	a, b := auditServer(t), auditServer(t)
	priv, pub := auditKey(t)
	body := auditSigned(t, "deposit", priv, pub, 100, 1)
	auditStatus(t, auditPost(a, "/deposit", body), 200)
	auditStatus(t, auditSyncEntries(t, b, a.v.Log.Entries()), 200)
	if b.v.R != 100 {
		t.Fatal("sync setup failed")
	}
	w := auditPost(b, "/deposit", body)
	if w.Code == 200 {
		t.Errorf("same signed request applied twice in B history: HTTP %d R=%d entries=%d nonce=%d",
			w.Code, b.v.R, b.v.Log.Len(), b.nonces[pub])
	}
}

func TestAudit_SyncRejectsUnbackedState(t *testing.T) {
	s := auditServer(t)
	priv, pub := auditKey(t)
	auditStatus(t, auditPost(s, "/deposit", auditSigned(t, "deposit", priv, pub, 100, 1)), 200)
	fake := ledger.New()
	fake.Append(`{"kind":"invented","amount":0,"reserves_after":100,"claims_after":100}`)
	fake.Append(`{"kind":"invented","amount":0,"reserves_after":0,"claims_after":1000000}`)
	w := auditSyncEntries(t, s, fake.Entries())
	if s.v.R != 100 || s.v.C != 100 {
		t.Errorf("unbacked state accepted: HTTP %d %s invariant_violations=%d chain_valid=%t",
			w.Code, w.Body.String(), s.m.InvariantViolations, s.v.Log.Verify() == nil)
	}
}

func TestAudit_FailedSyncMustNotPoisonRestart(t *testing.T) {
	s := auditServer(t)
	priv, pub := auditKey(t)
	auditStatus(t, auditPost(s, "/deposit", auditSigned(t, "deposit", priv, pub, 100, 1)), 200)
	fake := ledger.New()
	fake.Append(`{"kind":"deposit","amount":1,"reserves_after":1,"claims_after":1}`)
	fake.Append(`{not json`)
	w := auditSyncEntries(t, s, fake.Entries())
	_, restartErr := auditRestart(s)
	if restartErr != nil || s.v.Log.Len() != 1 {
		t.Errorf("rejected sync committed bad history: HTTP %d %s in-memory R=%d entries=%d; restart error=%v",
			w.Code, w.Body.String(), s.v.R, s.v.Log.Len(), restartErr)
	}
}

func TestAudit_HonestForkMustNotDiscardAcceptedDeposit(t *testing.T) {
	a, b := auditServer(t), auditServer(t)
	ap, au := auditKey(t)
	bp, bu := auditKey(t)
	auditStatus(t, auditPost(a, "/deposit", auditSigned(t, "deposit", ap, au, 100, 1)), 200)
	auditStatus(t, auditPost(b, "/deposit", auditSigned(t, "deposit", bp, bu, 50, 1)), 200)
	auditStatus(t, auditSyncEntries(t, a, b.v.Log.Entries()), 200)
	t.Logf("equal-length honest branches do not converge: A=%d B=%d", a.v.R, b.v.R)
	auditStatus(t, auditPost(b, "/deposit", auditSigned(t, "deposit", bp, bu, 1, 2)), 200)
	auditStatus(t, auditSyncEntries(t, a, b.v.Log.Entries()), 200)
	if a.v.R == 51 && a.nonces[au] == 1 {
		t.Errorf("A's accepted 100 erased by B's longer honest branch; A R=%d entries=%d; Alice nonce still=%d",
			a.v.R, a.v.Log.Len(), a.nonces[au])
	}
}

func TestAudit_JournalFailureMustNotApplySameSignatureRepeatedly(t *testing.T) {
	s := auditServer(t)
	priv, pub := auditKey(t)
	auditStatus(t, auditPost(s, "/deposit", auditSigned(t, "deposit", priv, pub, 100, 1)), 200)
	journal := filepath.Join(s.dataDir, "journal.jsonl")
	backup := journal + ".backup"
	if err := os.Rename(journal, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journal, 0700); err != nil {
		t.Fatal(err)
	}
	body := auditSigned(t, "redeem", priv, pub, 25, 2)
	first, second := auditPost(s, "/redeem", body), auditPost(s, "/redeem", body)
	auditStatus(t, first, 500)
	auditStatus(t, second, 500)
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, journal); err != nil {
		t.Fatal(err)
	}
	third := auditPost(s, "/redeem", body)
	auditStatus(t, third, 200)
	restarted, err := auditRestart(s)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.v.R != 75 {
		t.Errorf("one signature for 25 applied three times: statuses=%d,%d,%d; durable R=%d C=%d entries=%d nonce=%d",
			first.Code, second.Code, third.Code, restarted.v.R, restarted.v.C, restarted.v.Log.Len(), restarted.nonces[pub])
	}
}

func TestAudit_NonceWriteFailureMustNotEnableReplayOnRestart(t *testing.T) {
	s := auditServer(t)
	priv, pub := auditKey(t)
	auditStatus(t, auditPost(s, "/deposit", auditSigned(t, "deposit", priv, pub, 100, 1)), 200)
	if err := os.Mkdir(s.noncePath+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	body := auditSigned(t, "redeem", priv, pub, 25, 2)
	w := auditPost(s, "/redeem", body)
	auditStatus(t, w, 500)
	if err := os.Remove(s.noncePath + ".tmp"); err != nil {
		t.Fatal(err)
	}
	restarted, err := auditRestart(s)
	if err != nil {
		t.Fatal(err)
	}
	before := restarted.v.R
	replay := auditPost(restarted, "/redeem", body)
	if replay.Code == 200 {
		t.Errorf("durable redemption replayed after failed nonce save: before replay R=%d after=%d HTTP=%d entries=%d",
			before, restarted.v.R, replay.Code, restarted.v.Log.Len())
	}
}

type auditBlockedBody struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	reader  *strings.Reader
}

func (b *auditBlockedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started); <-b.release })
	return b.reader.Read(p)
}
func (b *auditBlockedBody) Close() error { return nil }

func TestAudit_PeerRequestBodyMustNotHoldGlobalLock(t *testing.T) {
	s := auditServer(t)
	body := &auditBlockedBody{started: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader(`{"url":"http://unused.invalid"}`)}
	req := httptest.NewRequest(http.MethodPost, "/peers", nil)
	req.Body = body
	peerDone := make(chan struct{})
	go func() { defer close(peerDone); s.handlePeers(httptest.NewRecorder(), req) }()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("body was not read")
	}
	lockAvailable := s.mu.TryLock()
	if lockAvailable {
		s.mu.Unlock()
	}
	stateDone := make(chan struct{})
	go func() {
		defer close(stateDone)
		s.handleState(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/state", nil))
	}()
	stateBlocked := false
	select {
	case <-stateDone:
	case <-time.After(50 * time.Millisecond):
		stateBlocked = true
	}
	close(body.release)
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("peer did not resume")
	}
	select {
	case <-stateDone:
	case <-time.After(time.Second):
		t.Fatal("state did not resume")
	}
	if !lockAvailable && stateBlocked {
		t.Error("one unauthenticated /peers request stalled while reading its body held global mutex and blocked /state until body resumed")
	}
}

func TestAudit_PeerURLMustNotTargetUnrelatedInternalPath(t *testing.T) {
	s := auditServer(t)
	seen := make(chan string, 1)
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer internal.Close()
	request, _ := json.Marshal(peerReq{URL: internal.URL + "/internal-control#"})
	auditStatus(t, auditPost(s, "/peers", request), 200)
	auditStatus(t, auditPost(s, "/sync", nil), 200)
	select {
	case actual := <-seen:
		if actual == "GET /internal-control" {
			t.Errorf("unauthenticated peer registration caused %s on loopback; appended /ledger became a fragment", actual)
		}
	default:
	}
}

func TestAudit_ControlUnsignedRequestRejected(t *testing.T) {
	s := auditServer(t)
	w := auditPost(s, "/deposit", []byte(`{"amount":100}`))
	if w.Code != 401 || s.v.R != 0 {
		t.Fatalf("unsigned request should be rejected: HTTP=%d R=%d", w.Code, s.v.R)
	}
}

func TestAudit_ControlOverflowFix(t *testing.T) {
	s := auditServer(t)
	priv, pub := auditKey(t)
	auditStatus(t, auditPost(s, "/deposit", auditSigned(t, "deposit", priv, pub, math.MaxInt64, 1)), 200)
	w := auditPost(s, "/deposit", auditSigned(t, "deposit", priv, pub, 1, 2))
	if w.Code != 422 || s.v.R != math.MaxInt64 || s.v.C != math.MaxInt64 || s.nonces[pub] != 1 {
		t.Fatalf("overflow rejection failed: HTTP=%d state=%v nonce=%d", w.Code, s.state(), s.nonces[pub])
	}
}
