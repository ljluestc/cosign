// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
    "context"
    "testing"
    "time"

    "github.com/google/go-containerregistry/pkg/name"
    "github.com/stretchr/testify/assert"
    "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
    "github.com/sigstore/cosign/v2/pkg/oci"
    ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
    "github.com/sigstore/rekor/pkg/generated/client"
    "github.com/sigstore/sigstore-go/pkg/bundle"
)

type mockSignatures struct {
    signatures []oci.Signature
    err        error
}

func (m *mockSignatures) Get() ([]oci.Signature, error) {
    if m.err != nil {
        return nil, m.err
    }
    return m.signatures, nil
}

type mockSignature struct {
    bundle *ociremote.Bundle
    digest name.Digest
    err    error
}

func (m *mockSignature) Bundle() (*ociremote.Bundle, error) {
    return m.bundle, m.err
}

func (m *mockSignature) Digest() (name.Digest, error) {
    return m.digest, m.err
}

func (m *mockSignature) Layers() ([]oci.Layer, error) {
    return nil, nil // Simplified for testing
}

func TestTlogCmdExec(t *testing.T) {
    tests := []struct {
        name        string
        imageRef    string
        opts        *options.TlogOptions
        sigs        *mockSignatures
        wantUUIDs   []string
        wantErr     bool
        errContains string
    }{
        {
            name:     "Valid image with UUIDs",
            imageRef: "testimage:latest",
            opts: &options.TlogOptions{
                RekorURL: "https://rekor.sigstore.dev",
                Timeout:  5 * time.Second,
            },
            sigs: &mockSignatures{
                signatures: []oci.Signature{
                    &mockSignature{
                        bundle: &ociremote.Bundle{
                            Bundle: &bundle.Bundle{
                                LogEntry: map[string]ociremote.LogEntry{
                                    "1": {LogID: "uuid1"},
                                    "2": {LogID: "uuid2"},
                                },
                            },
                        },
                        digest: name.Digest("sha256:abc123"),
                    },
                },
            },
            wantUUIDs: []string{"uuid1", "uuid2"},
            wantErr:   false,
        },
        {
            name:     "No tlog entries",
            imageRef: "testimage:latest",
            opts: &options.TlogOptions{
                RekorURL: "https://rekor.sigstore.dev",
                Timeout:  5 * time.Second,
            },
            sigs: &mockSignatures{
                signatures: []oci.Signature{
                    &mockSignature{},
                },
            },
            wantUUIDs: nil,
            wantErr:   false,
        },
        {
            name:     "Invalid image reference",
            imageRef: "invalid:image:reference",
            opts: &options.TlogOptions{
                RekorURL: "https://rekor.sigstore.dev",
                Timeout:  5 * time.Second,
            },
            sigs:        nil,
            wantUUIDs:   nil,
            wantErr:     true,
            errContains: "parsing image reference",
        },
        {
            name:     "Tag filter matches",
            imageRef: "testimage:latest",
            opts: &options.TlogOptions{
                RekorURL: "https://rekor.sigstore.dev",
                Timeout:  5 * time.Second,
                Tag:      "sha256-abc123.sig",
            },
            sigs: &mockSignatures{
                signatures: []oci.Signature{
                    &mockSignature{
                        bundle: &ociremote.Bundle{
                            Bundle: &bundle.Bundle{
                                LogEntry: map[string]ociremote.LogEntry{
                                    "1": {LogID: "uuid1"},
                                },
                            },
                        },
                        digest: name.Digest("sha256:abc123"),
                    },
                },
            },
            wantUUIDs: []string{"uuid1"},
            wantErr:   false,
        },
        {
            name:     "Tag filter no match",
            imageRef: "testimage:latest",
            opts: &options.TlogOptions{
                RekorURL: "https://rekor.sigstore.dev",
                Timeout:  5 * time.Second,
                Tag:      "sha256-xyz789.sig",
            },
            sigs: &mockSignatures{
                signatures: []oci.Signature{
                    &mockSignature{
                        bundle: &ociremote.Bundle{
                            Bundle: &bundle.Bundle{
                                LogEntry: map[string]ociremote.LogEntry{
                                    "1": {LogID: "uuid1"},
                                },
                            },
                        },
                        digest: name.Digest("sha256:abc123"),
                    },
                },
            },
            wantUUIDs: nil,
            wantErr:   false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Mock rekor client
            rekorClient := &client.Rekor{}

            // Mock digest resolution and signatures
            if tt.sigs != nil {
                origResolveDigest := ociremote.ResolveDigest
                origSignatures := ociremote.Signatures
                defer func() {
                    ociremote.ResolveDigest = origResolveDigest
                    ociremote.Signatures = origSignatures
                }()

                ociremote.ResolveDigest = func(ref name.Reference, opts ...ociremote.Option) (name.Digest, error) {
                    return name.Digest("sha256:abc123"), nil
                }
                ociremote.Signatures = func(digest name.Digest, opts ...ociremote.Option) (ociremote.Signatures, error) {
                    return tt.sigs, nil
                }
            }

            err := TlogCmdExec(context.Background(), tt.opts, tt.imageRef)
            if tt.wantErr {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.errContains)
                return
            }
            assert.NoError(t, err)

            // Verify fetchTlogUUIDs separately
            uuids, err := fetchTlogUUIDs(context.Background(), rekorClient, tt.sigs, tt.opts.Tag, name.Digest("sha256:abc123"))
            assert.NoError(t, err)
            assert.Equal(t, tt.wantUUIDs, uuids)
        })
    }
}