package cli

import (
    "testing"

    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

func TestVerifyOptions(t *testing.T) {
    o := &options.VerifyOptions{}
    cmd := &cobra.Command{}
    o.AddFlags(cmd)

    // Test flag presence
    assert.NotNil(t, cmd.Flags().Lookup("key"))
    assert.NotNil(t, cmd.Flags().Lookup("offline"))
    assert.NotNil(t, cmd.Flags().Lookup("output"))
    assert.Equal(t, "json", cmd.Flag("output").DefValue)
}