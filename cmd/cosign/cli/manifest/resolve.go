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

package manifest

import (
    "context"
    "fmt"
    "os"
    "path/filepath"

    "github.com/google/go-containerregistry/pkg/name"
    "github.com/google/go-containerregistry/pkg/v1/remote"
    "github.com/spf13/cobra"
    "sigs.k8s.io/kustomize/kyaml/yaml"
    "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

var remoteImageFunc = remote.Image

func ResolveCmd() *cobra.Command {
    o := &options.ResolveOptions{}

    cmd := &cobra.Command{
        Use:   "resolve",
        Short: "Resolve image tags to digests in Kubernetes manifests",
        Example: `  # Resolve tags in a single file
  cosign manifest resolve -f deployment.yaml -o resolved.yaml

  # Resolve tags in a directory and pipe to kubectl
  cosign manifest resolve -f ./manifests | kubectl apply -f -`,
        Args: cobra.NoArgs,
        RunE: func(cmd *cobra.Command, args []string) error {
            return ResolveCmdExec(cmd.Context(), o)
        },
    }

    o.AddFlags(cmd)
    return cmd
}

type ResolveOptions struct {
    File     string
    Output   string
    Registry options.RegistryOptions
}

func (o *ResolveOptions) AddFlags(cmd *cobra.Command) {
    cmd.Flags().StringVarP(&o.File, "file", "f", "", "path to manifest file or directory (required)")
    cmd.MarkFlagRequired("file")
    cmd.Flags().StringVarP(&o.Output, "output", "o", "", "output file (if empty, output to stdout)")
    o.Registry.AddFlags(cmd)
}

func ResolveCmdExec(ctx context.Context, o *ResolveOptions) error {
    ociremoteOpts, err := o.Registry.ClientOpts(ctx)
    if err != nil {
        return fmt.Errorf("getting registry client options: %w", err)
    }

    // Handle file or directory input
    info, err := os.Stat(o.File)
    if err != nil {
        return fmt.Errorf("accessing file: %w", err)
    }

    var manifests []*yaml.RNode
    if info.IsDir() {
        manifests, err = processDir(o.File)
    } else {
        manifests, err = processFile(o.File)
    }
    if err != nil {
        return err
    }

    // Resolve tags to digests
    for _, node := range manifests {
        if err := resolveImages(ctx, node, ociremoteOpts); err != nil {
            return fmt.Errorf("resolving images: %w", err)
        }
    }

    // Output results
    var output []byte
    for i, node := range manifests {
        data, err := node.String()
        if err != nil {
            return fmt.Errorf("converting node to string: %w", err)
        }
        if i > 0 {
            output = append(output, []byte("---\n")...)
        }
        output = append(output, []byte(data)...)
    }

    if o.Output != "" {
        if err := os.WriteFile(o.Output, output, 0644); err != nil {
            return fmt.Errorf("writing output file: %w", err)
        }
    } else {
        _, err = os.Stdout.Write(output)
        if err != nil {
            return fmt.Errorf("writing to stdout: %w", err)
        }
    }

    return nil
}

func processFile(file string) ([]*yaml.RNode, error) {
    data, err := os.ReadFile(file)
    if err != nil {
        return nil, fmt.Errorf("reading file: %w", err)
    }

    nodes, err := yaml.Parse(string(data))
    if err != nil {
        return nil, fmt.Errorf("parsing YAML: %w", err)
    }

    return []*yaml.RNode{nodes}, nil
}

func processDir(dir string) ([]*yaml.RNode, error) {
    var nodes []*yaml.RNode
    err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if info.IsDir() || (filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml") {
            return nil
        }
        fileNodes, err := processFile(path)
        if err != nil {
            return err
        }
        nodes = append(nodes, fileNodes...)
        return nil
    })
    if err != nil {
        return nil, fmt.Errorf("walking directory: %w", err)
    }
    return nodes, nil
}

func resolveImages(ctx context.Context, node *yaml.RNode, opts []remote.Option) error {
    kind, err := node.Field("kind")
    if err != nil {
        return nil // Skip if no kind
    }

    paths := map[string][]string{
        "Deployment":  {"spec", "template", "spec", "containers", "*", "image"},
        "DaemonSet":   {"spec", "template", "spec", "containers", "*", "image"},
        "ReplicaSet":  {"spec", "template", "spec", "containers", "*", "image"},
        "StatefulSet": {"spec", "template", "spec", "containers", "*", "image"},
        "CronJob":     {"spec", "jobTemplate", "spec", "template", "spec", "containers", "*", "image"},
    }

    path, ok := paths[kind.Value.YNode().Value]
    if !ok {
        return nil // Skip unsupported kinds
    }

    images, err := node.Pipe(yaml.Lookup(path...))
    if err != nil || images == nil {
        return nil // Skip if path not found
    }

    return images.VisitElements(func(img *yaml.RNode) error {
        imgStr, err := img.String()
        if err != nil {
            return err
        }

        ref, err := name.ParseReference(imgStr)
        if err != nil {
            return nil // Skip invalid references
        }

        remoteImg, err := remoteImageFunc(ref, opts...)
        if err != nil {
            return nil // Skip unresolvable tags
        }

        digest, err := remoteImg.Digest()
        if err != nil {
            return nil // Skip if digest can't be retrieved
        }

        newImg := fmt.Sprintf("%s@%s", ref.Context().Name(), digest.String())
        return img.SetString(newImg)
    })
}