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

package manifest

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"

    "github.com/google/go-containerregistry/pkg/name"
    v1 "github.com/google/go-containerregistry/pkg/v1"
    "github.com/google/go-containerregistry/pkg/v1/remote"
    "github.com/spf13/cobra"
    "sigs.k8s.io/kustomize/kyaml/yaml"
    "github.com/stretchr/testify/assert"
)

// mockRemoteImage is a mock for remote.Image to avoid real registry calls
type mockRemoteImage struct{}

func (m *mockRemoteImage) Digest() (v1.Hash, error) {
    return v1.Hash{Algorithm: "sha256", Hex: "mockeddigest1234567890abcdef1234567890abcdef"}, nil
}

func TestResolveCmd(t *testing.T) {
    tests := []struct {
        name          string
        inputManifest string
        expectedImage string
        wantErr       bool
        outputToFile  bool
    }{
        {
            name: "Resolve Deployment Image",
            inputManifest: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: test-container
        image: nginx:latest`,
            expectedImage: "nginx@sha256:mockeddigest1234567890abcdef1234567890abcdef",
            wantErr:       false,
            outputToFile:  false,
        },
        {
            name: "Resolve to File",
            inputManifest: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  template:
    spec:
      containers:
      - name: test-container
        image: busybox:1.35`,
            expectedImage: "busybox@sha256:mockeddigest1234567890abcdef1234567890abcdef",
            wantErr:       false,
            outputToFile:  true,
        },
        {
            name:          "Invalid Manifest",
            inputManifest: `invalid yaml`,
            wantErr:       true,
            outputToFile:  false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create a temporary directory for testing
            tempDir := t.TempDir()
            inputFile := filepath.Join(tempDir, "input.yaml")
            if err := os.WriteFile(inputFile, []byte(tt.inputManifest), 0644); err != nil {
                t.Fatalf("Failed to write input file: %v", err)
            }

            // Set up the command
            cmd := ResolveCmd()
            o := &ResolveOptions{
                File: inputFile,
            }
            if tt.outputToFile {
                o.Output = filepath.Join(tempDir, "output.yaml")
            }
            // Set flags directly
            cmd.SetArgs([]string{"-f", o.File})
            if o.Output != "" {
                cmd.SetArgs(append(cmd.Args(), "-o", o.Output))
            }

            // Mock remoteImageFunc
            originalRemoteImageFunc := remoteImageFunc
            remoteImageFunc = func(ref name.Reference, options ...remote.Option) (remote.Image, error) {
                return &mockRemoteImage{}, nil
            }
            defer func() { remoteImageFunc = originalRemoteImageFunc }()

            // Capture stdout
            oldStdout := os.Stdout
            r, w, _ := os.Pipe()
            os.Stdout = w
            defer func() { os.Stdout = oldStdout }()

            // Run the command
            err := cmd.Execute()
            w.Close()

            if (err != nil) != tt.wantErr {
                t.Errorf("ResolveCmd() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if tt.wantErr {
                return
            }

            // Read output
            var output []byte
            if tt.outputToFile {
                output, err = os.ReadFile(o.Output)
                if err != nil {
                    t.Fatalf("Failed to read output file: %v", err)
                }
            } else {
                var buf bytes.Buffer
                _, err = buf.ReadFrom(r)
                if err != nil {
                    t.Fatalf("Failed to read stdout: %v", err)
                }
                output = buf.Bytes()
            }

            // Parse output YAML
            nodes, err := yaml.Parse(string(output))
            if err != nil {
                t.Fatalf("Failed to parse output YAML: %v", err)
            }

            // Check resolved image
            containers, err := nodes.Pipe(yaml.Lookup("spec", "template", "spec", "containers", "0", "image"))
            if err != nil || containers == nil {
                t.Fatalf("Failed to find image in output: %v", err)
            }
            img, err := containers.String()
            if err != nil {
                t.Fatalf("Failed to get image string: %v", err)
            }
            if img != tt.expectedImage {
                t.Errorf("Resolved image = %v, want %v", img, tt.expectedImage)
            }
        })
    }
}