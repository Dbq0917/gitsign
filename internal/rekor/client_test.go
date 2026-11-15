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

package rekor

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

	"github.com/sigstore/cosign/v3/pkg/cosign"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
)

func TestRekorKeysFromTrustedRoot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := sgroot.NewTrustedRoot(
		sgroot.TrustedRootMediaType01,
		nil,
		nil,
		nil,
		map[string]*sgroot.TransparencyLog{
			"rekor": {
				BaseURL:             "https://rekor.example.com",
				ID:                  []byte("rekor-log-id"),
				ValidityPeriodStart: time.Unix(0, 0),
				HashFunc:            crypto.SHA256,
				PublicKey:           &key.PublicKey,
				SignatureHashFunc:   crypto.SHA256,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := rekorKeysFromTrustedRoot(path)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantID, err := cosign.GetTransparencyLogID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys.Keys[wantID]; !ok {
		t.Errorf("Rekor key map does not contain log ID %s", wantID)
	}
}
