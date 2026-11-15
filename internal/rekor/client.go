// Copyright 2022 The Sigstore Authors
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
	"fmt"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/gitsign/internal/sigstore/localcache"
	gitrekor "github.com/sigstore/gitsign/pkg/rekor"
	rekor "github.com/sigstore/rekor/pkg/client"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
)

// NewClient returns a new Rekor client with common client options set.
//
// Deprecated: Use NewClientContext instead.
func NewClient(url string) (*gitrekor.Client, error) {
	return NewClientContext(context.TODO(), url)
}

// NewClientContext returns a new Rekor client with common client options set.
// When a local sigstore-go trusted root is present, its Rekor public keys are
// used instead of sigstore/sigstore's TUF client, whose embedded root can
// expire and break verification.
func NewClientContext(ctx context.Context, url string) (*gitrekor.Client, error) {
	opts := []gitrekor.Option{gitrekor.WithClientOption(rekor.WithUserAgent("gitsign"))}
	if path, ok := localcache.TrustedRootPath(); ok {
		opts = append(opts, gitrekor.WithCosignRekorKeyProvider(rekorKeysFromTrustedRoot(path)))
	}
	return gitrekor.NewWithOptions(ctx, url, opts...)
}

func rekorKeysFromTrustedRoot(path string) gitrekor.CosignRekorKeyProvider {
	return func(_ context.Context) (*cosign.TrustedTransparencyLogPubKeys, error) {
		tr, err := sgroot.NewTrustedRootFromPath(path)
		if err != nil {
			return nil, fmt.Errorf("loading trusted root %s: %w", path, err)
		}

		keys := cosign.NewTrustedTransparencyLogPubKeys()
		for _, log := range tr.RekorLogs() {
			pem, err := cryptoutils.MarshalPublicKeyToPEM(log.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("marshalling Rekor public key: %w", err)
			}
			// AddTransparencyLogPubKey derives the same log ID cosign uses when
			// loading keys through TUF.
			if err := keys.AddTransparencyLogPubKey(pem, tuf.Active); err != nil {
				return nil, fmt.Errorf("adding Rekor public key: %w", err)
			}
		}
		if len(keys.Keys) == 0 {
			return nil, fmt.Errorf("no Rekor public keys in trusted root %s", path)
		}
		return &keys, nil
	}
}
