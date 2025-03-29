// Copyright 2021 The Sigstore Authors.
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
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
)

// AttestationCmd attaches attestations to an image from a list of signed payload files.
func AttestationCmd(ctx context.Context, regOpts options.RegistryOptions, signedPayloads []string, imageRef string) error {
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	for _, payload := range signedPayloads {
		if err := attachAttestation(ctx, ociremoteOpts, payload, imageRef, regOpts.NameOptions()); err != nil {
			return fmt.Errorf("attaching payload from %s: %w", payload, err)
		}
	}

	return nil
}

// attachAttestation attaches a single attestation to the specified image.
func attachAttestation(ctx context.Context, remoteOpts []ociremote.Option, signedPayload, imageRef string, nameOpts []name.Option) error {
	fmt.Fprintf(os.Stderr, "Using payload from: %s\n", signedPayload)
	attestationFile, err := os.Open(signedPayload)
	if err != nil {
		return err
	}
	defer attestationFile.Close()

	env := ssldsse.Envelope{}
	decoder := json.NewDecoder(attestationFile)
	for decoder.More() {
		if err := decoder.Decode(&env); err != nil {
			return err
		}

		payload, err := json.Marshal(env)
		if err != nil {
			return err
		}

		if env.PayloadType != types.IntotoPayloadType {
			return fmt.Errorf("invalid payloadType %s on envelope; expected %s", env.PayloadType, types.IntotoPayloadType)
		}

		if len(env.Signatures) == 0 {
			return fmt.Errorf("cannot attach attestation without signatures")
		}

		ref, err := name.ParseReference(imageRef, nameOpts...)
		if err != nil {
			return err
		}
		if _, ok := ref.(name.Digest); !ok {
			msg := fmt.Sprintf(ui.TagReferenceMessage, imageRef)
			ui.Warnf(ctx, msg)
		}
		digest, err := ociremote.ResolveDigest(ref, remoteOpts...)
		if err != nil {
			return err
		}
		// Overwrite "ref" with a digest to avoid race conditions with tags.
		ref = digest

		opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
		att, err := static.NewAttestation(payload, opts...)
		if err != nil {
			return err
		}

		se, err := ociremote.SignedEntity(digest, remoteOpts...)
		if err != nil {
			return err
		}

		newSE, err := mutate.AttachAttestationToEntity(se, att)
		if err != nil {
			return err
		}

		if err = ociremote.WriteAttestations(digest.Repository, newSE, remoteOpts...); err != nil {
			return err
		}
	}
	return nil
}
