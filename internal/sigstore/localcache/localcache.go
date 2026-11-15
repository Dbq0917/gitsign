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

// Package localcache locates a sigstore-go-style TUF cache on disk and exposes
// the trusted_root.json it contains. Verification prefers this cache over
// sigstore/sigstore's TUF client, whose embedded root can expire and break
// otherwise valid signatures.
package localcache

import (
	"encoding/json"
	"os"
	"path/filepath"

	sgtuf "github.com/sigstore/sigstore-go/pkg/tuf"
)

// TrustedRootPath returns the path to a cached sigstore-go trusted_root.json
// under $TUF_ROOT (or ~/.sigstore/root by default). The mirror URL is read from
// remote.json in the same directory and converted to its on-disk directory
// using sigstore-go's cache layout. It returns false if any prerequisite is
// missing.
func TrustedRootPath() (string, bool) {
	cacheRoot := os.Getenv("TUF_ROOT")
	if cacheRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", false
		}
		cacheRoot = filepath.Join(home, ".sigstore", "root")
	}

	remoteBytes, err := os.ReadFile(filepath.Join(cacheRoot, "remote.json"))
	if err != nil {
		return "", false
	}
	var remote struct {
		Mirror string `json:"mirror"`
	}
	if err := json.Unmarshal(remoteBytes, &remote); err != nil || remote.Mirror == "" {
		return "", false
	}

	path := filepath.Join(cacheRoot, sgtuf.URLToPath(remote.Mirror), "targets", "trusted_root.json")
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return "", false
	}
	return path, true
}
