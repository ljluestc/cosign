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

package attach

import (
    "context"
    "os"
    "path/filepath"
    "testing"

    "github.com/google/go-containerregistry/pkg/name"
    "github.com/google/go-containerregistry/pkg/v1/remote"
    "github.com/stretchr/testify/assert"
    "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
    "github.com/sigstore/cosign/v2/pkg/oci"
    ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
    "github.com/sigstore/cosign/v2/pkg/types"
)

type mockSignedEntity struct {
    attached bool
}

func (m *mockSignedEntity) Signatures() (oci.Signatures, error) {
    return nil, nil // Not needed for this test
}

func (m *mockSignedEntity) Attestations() (oci.Signatures, error) {
    return nil, nil // Not needed for this test
}

func (m *mockSignedEntity) AttachAttestation(att oci.Signature) (oci.SignedEntity, error) {
    m.attached = true
    return m, nil
}

func TestAttestationCmd(t *testing.T) {
    tests := []struct {
        name         string
        payloadFile  string
        payloadData  string
        imageRef     string
        wantErr      bool
        errContains  string
    }{
        {
            name:        "Valid attestation",
            payloadFile: "valid_attestation.json",
            payloadData: `{
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"keyid": "test", "sig": "dummysig"}],
                "payload": "eyJzdGF0ZW1lbnQiOiJ0ZXN0In0="
            }`,
            imageRef:    "test/image@sha256:abcd1234",
            wantErr:     false,
        },
        {
            name:        "Invalid payload type",
            payloadFile: "invalid_type.json",
            payloadData: `{"payloadType": "wrong/type", "signatures": [{"keyid": "test", "sig": "dummysig"}]}`,
            imageRef:    "test/image@sha256:abcd1234",
            wantErr:     true,
            errContains: "invalid payloadType",
        },
        {
            name:        "No signatures",
            payloadFile: "no_sigs.json",
            payloadData: `{"payloadType": "application/vnd.in-toto+json"}`,
            imageRef:    "test/image@sha256:abcd1234",
            wantErr:     true,
            errContains: "without signatures",
        },
        {
            name:        "Invalid file",
            payloadFile: "nonexistent.json",
            payloadData: "",
            imageRef:    "test/image@sha256:abcd1234",
            wantErr:     true,
            errContains: "no such file",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup temp directory and payload file
            tempDir := t.TempDir()
            payloadPath := filepath.Join(tempDir, tt.payloadFile)
            if tt.payloadData != "" {
                err := os.WriteFile(payloadPath, []byte(tt.payloadData), 0644)
                assert.NoError(t, err)
            }

            // Mock remote functions
            originalResolveDigest := ociremote.ResolveDigest
            originalSignedEntity := ociremote.SignedEntity
            originalWriteAttestations := ociremote.WriteAttestations
            originalImage := remote.Image
            defer func() {
                ociremote.ResolveDigest = originalResolveDigest
                ociremote.SignedEntity = originalSignedEntity
                ociremote.WriteAttestations = originalWriteAttestations
                remote.Image = originalImage
            }()

            ociremote.ResolveDigest = func(ref name.Reference, opts ...ociremote.Option) (name.Digest, error) {
                return name.Digest(tt.imageRef), nil
            }
            ociremote.SignedEntity = func(digest name.Digest, opts ...ociremote.Option) (oci.SignedEntity, error) {
                return &mockSignedEntity{}, nil
            }
            ociremote.WriteAttestations = func(repo name.Repository, se oci.SignedEntity, opts ...ociremote.Option) error {
                return nil
            }
            remote.Image = func(ref name.Reference, opts ...remote.Option) (remote.Image, error) {
                return nil, nil // Not needed for this test
            }

            // Test AttestationCmd
            regOpts := options.RegistryOptions{}
            err := AttestationCmd(context.Background(), regOpts, []string{payloadPath}, tt.imageRef)
            if tt.wantErr {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.errContains)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}