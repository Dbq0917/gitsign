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

package localcache

import (
	"os"
	"path/filepath"
	"testing"

	sgtuf "github.com/sigstore/sigstore-go/pkg/tuf"
)

const testMirror = "https://tuf.example.com/custom"

func TestTrustedRootPath(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("TUF_ROOT", cacheRoot)

	writeRemote(t, cacheRoot, testMirror)
	targets := filepath.Join(cacheRoot, sgtuf.URLToPath(testMirror), "targets")
	if err := os.MkdirAll(targets, 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(targets, "trusted_root.json")
	if err := os.WriteFile(want, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, ok := TrustedRootPath()
	if !ok {
		t.Fatal("TrustedRootPath() did not find a cached trusted root")
	}
	if got != want {
		t.Errorf("TrustedRootPath() = %q, want %q", got, want)
	}
}

func TestTrustedRootPathDefaultCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TUF_ROOT", "")

	cacheRoot := filepath.Join(home, ".sigstore", "root")
	writeRemote(t, cacheRoot, testMirror)
	targets := filepath.Join(cacheRoot, sgtuf.URLToPath(testMirror), "targets")
	if err := os.MkdirAll(targets, 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(targets, "trusted_root.json")
	if err := os.WriteFile(want, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, ok := TrustedRootPath()
	if !ok {
		t.Fatal("TrustedRootPath() did not find the default cached trusted root")
	}
	if got != want {
		t.Errorf("TrustedRootPath() = %q, want %q", got, want)
	}
}

func TestTrustedRootPathMissing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, cacheRoot string)
	}{
		{
			name:  "no remote",
			setup: func(*testing.T, string) {},
		},
		{
			name: "invalid remote",
			setup: func(t *testing.T, cacheRoot string) {
				if err := os.WriteFile(filepath.Join(cacheRoot, "remote.json"), []byte("not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "empty mirror",
			setup: func(t *testing.T, cacheRoot string) {
				writeRemote(t, cacheRoot, "")
			},
		},
		{
			name: "no trusted root",
			setup: func(t *testing.T, cacheRoot string) {
				writeRemote(t, cacheRoot, testMirror)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cacheRoot := t.TempDir()
			t.Setenv("TUF_ROOT", cacheRoot)
			tc.setup(t, cacheRoot)

			if path, ok := TrustedRootPath(); ok {
				t.Errorf("TrustedRootPath() = %q, true; want false", path)
			}
		})
	}
}

func writeRemote(t *testing.T, cacheRoot, mirror string) {
	t.Helper()
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	remote := []byte(`{"mirror":"` + mirror + `"}`)
	if err := os.WriteFile(filepath.Join(cacheRoot, "remote.json"), remote, 0o600); err != nil {
		t.Fatal(err)
	}
}
