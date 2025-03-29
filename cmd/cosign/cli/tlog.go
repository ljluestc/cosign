// Copyright 2022 The Sigstore Authors.
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
    "fmt"
    "os"
    "time"

    "github.com/google/go-containerregistry/pkg/name"
    "github.com/spf13/cobra"
    "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
    "github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
    ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
    "github.com/sigstore/rekor/pkg/generated/client"
)

func TlogCmd() *cobra.Command {
    o := &options.TlogOptions{}

    cmd := &cobra.Command{
        Use:   "tlog",
        Short: "Fetch all Rekor tlog UUIDs for a given image reference",
        Example: `  cosign tlog <IMAGE> --rekor-url <URL> --timeout <DURATION>
  
  # Fetch UUIDs for an image
  cosign tlog myimage:tag --rekor-url https://rekor.sigstore.dev
  
  # Filter by a specific signature tag
  cosign tlog myimage:tag --tag sha256-<SIG_SHA>.sig`,
        Args: cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            return TlogCmdExec(cmd.Context(), o, args[0])
        },
    }

    o.AddFlags(cmd)
    return cmd
}

func TlogCmdExec(ctx context.Context, o *options.TlogOptions, imageRef string) error {
    ref, err := name.ParseReference(imageRef)
    if err != nil {
        return fmt.Errorf("parsing image reference: %w", err)
    }

    ctx, cancel := context.WithTimeout(ctx, o.Timeout)
    defer cancel()

    rekorClient, err := rekor.NewClient(o.RekorURL)
    if err != nil {
        return fmt.Errorf("creating Rekor client: %w", err)
    }

    ociremoteOpts, err := o.RegistryClientOpts(ctx)
    if err != nil {
        return fmt.Errorf("getting registry client options: %w", err)
    }
    digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
    if err != nil {
        return fmt.Errorf("resolving image digest: %w", err)
    }

    sigs, err := ociremote.Signatures(digest, ociremoteOpts...)
    if err != nil {
        return fmt.Errorf("fetching signatures: %w", err)
    }

    uuids, err := fetchTlogUUIDs(ctx, rekorClient, sigs, o.Tag, digest)
    if err != nil {
        return fmt.Errorf("fetching tlog UUIDs: %w", err)
    }

    if len(uuids) == 0 {
        fmt.Fprintln(os.Stderr, "no matching tlog entries found")
        return nil
    }

    fmt.Fprintf(os.Stderr, "Found %d matching entries (listed by UUID):\n", len(uuids))
    for _, uuid := range uuids {
        fmt.Println(uuid)
    }
    return nil
}

func fetchTlogUUIDs(ctx context.Context, rekorClient *client.Rekor, sigs ociremote.Signatures, tagFilter string, digest name.Digest) ([]string, error) {
    var uuids []string

    signatures, err := sigs.Get()
    if err != nil {
        return nil, fmt.Errorf("getting signatures: %w", err)
    }

    for _, sig := range signatures {
        if tagFilter != "" {
            sigDigest, err := sig.Digest()
            if err != nil {
                continue
            }
            sigTag := fmt.Sprintf("sha256-%s.sig", sigDigest.Hex)
            if tagFilter != sigTag {
                continue
            }
        }

        bundle, err := sig.Bundle()
        if err != nil {
            continue // Skip if no bundle (not uploaded to tlog)
        }
        if bundle != nil && bundle.Bundle != nil && len(bundle.LogEntry) > 0 {
            for _, entry := range bundle.LogEntry {
                if entry.LogID != "" {
                    uuids = append(uuids, entry.LogID)
                }
            }
        }
    }

    return uuids, nil
}