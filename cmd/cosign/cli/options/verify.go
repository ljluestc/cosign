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

package options

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/v2/internal/pkg/cosign"
)

// CommonVerifyOptions defines shared options for all verify commands.
type CommonVerifyOptions struct {
	Offline               bool   // Force offline verification
	TSACertChainPath      string // Path to TSA certificate chain
	IgnoreTlog            bool   // Skip transparency log verification
	MaxWorkers            int    // Maximum number of parallel workers
	ExperimentalOCI11     bool   // Enable experimental OCI 1.1 behavior
	PrivateInfrastructure bool   // Indicate private infrastructure (implies IgnoreTlog)
	UseSignedTimestamps   bool   // Verify RFC3161 timestamps
	NewBundleFormat       bool   // Expect new Sigstore bundle format
	TrustedRootPath       string // Path to trusted root JSON file
}

// AddFlags adds common verification flags to the command.
func (o *CommonVerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.Offline, "offline", false,
		"only allow offline verification")

	cmd.Flags().StringVar(&o.TSACertChainPath, "timestamp-certificate-chain", "",
		"path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. "+
			"Optionally may contain intermediate CA certificates, and may contain the leaf TSA certificate if not present in the timestamp")

	cmd.Flags().BoolVar(&o.UseSignedTimestamps, "use-signed-timestamps", false,
		"verify RFC3161 timestamps")

	cmd.Flags().BoolVar(&o.IgnoreTlog, "insecure-ignore-tlog", false,
		"ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. "+
			"Artifacts cannot be publicly verified when not included in a log")

	cmd.Flags().BoolVar(&o.PrivateInfrastructure, "private-infrastructure", false,
		"skip transparency log verification when verifying artifacts in a privately deployed infrastructure")

	cmd.Flags().BoolVar(&o.ExperimentalOCI11, "experimental-oci11", false,
		"set to true to enable experimental OCI 1.1 behavior")

	cmd.Flags().IntVar(&o.MaxWorkers, "max-workers", cosign.DefaultMaxWorkers,
		"maximum number of workers for parallel executions")

	cmd.Flags().StringVar(&o.TrustedRootPath, "trusted-root", "",
		"path to a Sigstore TrustedRoot JSON file; requires --new-bundle-format to be set")

	cmd.Flags().BoolVar(&o.NewBundleFormat, "new-bundle-format", false,
		"expect the signature/attestation to be packaged in a Sigstore bundle")
}

// VerifyOptions is the top-level options struct for the `verify` command.
type VerifyOptions struct {
	Key          string
	CheckClaims  bool
	Attachment   string
	Output       string
	SignatureRef string
	PayloadRef   string
	LocalImage   bool

	CommonVerifyOptions CommonVerifyOptions
	SecurityKey         SecurityKeyOptions
	CertVerify          CertVerifyOptions
	Rekor               RekorOptions
	Registry            RegistryOptions
	SignatureDigest     SignatureDigestOptions

	AnnotationOptions
}

var _ Interface = (*VerifyOptions)(nil)

// AddFlags implements Interface for VerifyOptions.
func (o *VerifyOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.SignatureDigest.AddFlags(cmd)
	o.AnnotationOptions.AddFlags(cmd)
	o.CommonVerifyOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI, or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found in the signature")

	cmd.Flags().StringVar(&o.Attachment, "attachment", "",
		"DEPRECATED: related image attachment to verify (e.g., sbom), default none")
	_ = cmd.MarkFlagFilename("attachment", sbomExts...)

	cmd.Flags().StringVarP(&o.Output, "output", "o", "json",
		"output format for the verification result (json|text)")

	cmd.Flags().StringVar(&o.SignatureRef, "signature", "",
		"signature content, path, or remote URL")
	_ = cmd.MarkFlagFilename("signature", signatureExts...)

	cmd.Flags().StringVar(&o.PayloadRef, "payload", "",
		"payload path or remote URL")
	// _ = cmd.MarkFlagFilename("payload") // No typical extensions

	cmd.Flags().BoolVar(&o.LocalImage, "local-image", false,
		"whether the specified image is a local path saved via 'cosign save'")
}

// VerifyAttestationOptions is the top-level options struct for the `verify-attestation` command.
type VerifyAttestationOptions struct {
	Key         string
	CheckClaims bool
	Output      string

	CommonVerifyOptions CommonVerifyOptions
	SecurityKey         SecurityKeyOptions
	Rekor               RekorOptions
	CertVerify          CertVerifyOptions
	Registry            RegistryOptions
	Predicate           PredicateRemoteOptions
	Policies            []string
	LocalImage          bool
}

var _ Interface = (*VerifyAttestationOptions)(nil)

// AddFlags implements Interface for VerifyAttestationOptions.
func (o *VerifyAttestationOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.Predicate.AddFlags(cmd)
	o.CommonVerifyOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI, or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found in the attestation")

	cmd.Flags().StringSliceVar(&o.Policies, "policy", nil,
		"specify CUE or Rego files with policies for validation")

	cmd.Flags().StringVarP(&o.Output, "output", "o", "json",
		"output format for the verification result (json|text)")

	cmd.Flags().BoolVar(&o.LocalImage, "local-image", false,
		"whether the specified image is a local path saved via 'cosign save'")
}

// VerifyBlobOptions is the top-level options struct for the `verify-blob` command.
type VerifyBlobOptions struct {
	Key        string
	Signature  string
	BundlePath string

	SecurityKey         SecurityKeyOptions
	CertVerify          CertVerifyOptions
	Rekor               RekorOptions
	CommonVerifyOptions CommonVerifyOptions

	RFC3161TimestampPath string
}

var _ Interface = (*VerifyBlobOptions)(nil)

// AddFlags implements Interface for VerifyBlobOptions.
func (o *VerifyBlobOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.CommonVerifyOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI, or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().StringVar(&o.Signature, "signature", "",
		"signature content, path, or remote URL")
	_ = cmd.MarkFlagFilename("signature", signatureExts...)

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"path to Sigstore bundle file")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)

	cmd.Flags().StringVar(&o.RFC3161TimestampPath, "rfc3161-timestamp", "",
		"path to RFC3161 timestamp file")
	_ = cmd.MarkFlagFilename("rfc3161-timestamp", timestampExts...)
}

// VerifyDockerfileOptions is the top-level options struct for the `dockerfile verify` command.
type VerifyDockerfileOptions struct {
	VerifyOptions
	BaseImageOnly bool
}

var _ Interface = (*VerifyDockerfileOptions)(nil)

// AddFlags implements Interface for VerifyDockerfileOptions.
func (o *VerifyDockerfileOptions) AddFlags(cmd *cobra.Command) {
	o.VerifyOptions.AddFlags(cmd)

	cmd.Flags().BoolVar(&o.BaseImageOnly, "base-image-only", false,
		"only verify the base image (the last FROM image in the Dockerfile)")
}

// VerifyBlobAttestationOptions is the top-level options struct for the `verify-blob-attestation` command.
type VerifyBlobAttestationOptions struct {
	Key           string
	SignaturePath string
	BundlePath    string

	PredicateOptions
	CheckClaims bool

	SecurityKey         SecurityKeyOptions
	CertVerify          CertVerifyOptions
	Rekor               RekorOptions
	CommonVerifyOptions CommonVerifyOptions

	RFC3161TimestampPath string
}

var _ Interface = (*VerifyBlobAttestationOptions)(nil)

// AddFlags implements Interface for VerifyBlobAttestationOptions.
func (o *VerifyBlobAttestationOptions) AddFlags(cmd *cobra.Command) {
	o.PredicateOptions.AddFlags(cmd)
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.CommonVerifyOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI, or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().StringVar(&o.SignaturePath, "signature", "",
		"path to base64-encoded signature over attestation in DSSE format")
	_ = cmd.MarkFlagFilename("signature", signatureExts...)

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"path to Sigstore bundle file")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"if true, verifies the provided blob's SHA256 digest exists as an in-toto subject within the attestation; if false, only verifies the DSSE envelope")

	cmd.Flags().StringVar(&o.RFC3161TimestampPath, "rfc3161-timestamp", "",
		"path to RFC3161 timestamp file")
	_ = cmd.MarkFlagFilename("rfc3161-timestamp", timestampExts...)
}

// File extension constants (ensure these match Cosign's conventions)
var (
	publicKeyExts = []string{"pub"}
	sbomExts      = []string{"json", "spdx", "cyclonedx"}
	signatureExts = []string{"sig"}
	bundleExts    = []string{"json"}
	timestampExts = []string{"ts"}
)
