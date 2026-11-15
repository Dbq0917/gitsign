// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitsign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/sigstore/gitsign/internal/config"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	sgtuf "github.com/sigstore/sigstore-go/pkg/tuf"
)

const trustedRootTestMirror = "https://tuf.example.com"

func TestTimestampAuthoritiesFromLocalTrustedRoot(t *testing.T) {
	ca := fakeca.New()
	tr, err := sgroot.NewTrustedRoot(
		sgroot.TrustedRootMediaType01,
		nil,
		nil,
		[]sgroot.TimestampingAuthority{&sgroot.SigstoreTimestampingAuthority{Root: ca.Certificate}},
		nil,
	)
	writeLocalTrustedRoot(t, tr, err)

	authorities, err := timestampAuthorities(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(authorities) != 1 {
		t.Fatalf("timestampAuthorities() returned %d authorities, want 1", len(authorities))
	}
}

func TestCTLogPubsFromLocalTrustedRoot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := sgroot.NewTrustedRoot(
		sgroot.TrustedRootMediaType01,
		nil,
		map[string]*sgroot.TransparencyLog{
			"ct": {
				BaseURL:             "https://ct.example.com",
				ID:                  []byte("ct-log-id"),
				ValidityPeriodStart: time.Unix(0, 0),
				HashFunc:            crypto.SHA256,
				PublicKey:           &key.PublicKey,
				SignatureHashFunc:   crypto.SHA256,
			},
		},
		nil,
		nil,
	)
	writeLocalTrustedRoot(t, tr, err)

	keys, err := getCTLogPubs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("getCTLogPubs() returned %d keys, want 1", len(keys.Keys))
	}
}

func writeLocalTrustedRoot(t *testing.T, tr *sgroot.TrustedRoot, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	b, err := tr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	cacheRoot := t.TempDir()
	t.Setenv("TUF_ROOT", cacheRoot)
	if err := os.WriteFile(filepath.Join(cacheRoot, "remote.json"), []byte(`{"mirror":"`+trustedRootTestMirror+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join(cacheRoot, sgtuf.URLToPath(trustedRootTestMirror), "targets")
	if err := os.MkdirAll(targets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targets, "trusted_root.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
