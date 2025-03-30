package cosign
import (
    "context"
    "testing"
    "os"
    "github.com/stretchr/testify/assert"
)

func TestRekorTreeStateTracking(t *testing.T) {
    // Setup test environment
    tempDir := t.TempDir()
    originalHome := os.Getenv("HOME")
    os.Setenv("HOME", tempDir)
    defer os.Setenv("HOME", originalHome)
    
    ctx := context.Background()
    
    // Test with public Rekor instance
    rekorURL := "https://rekor.sigstore.dev"
    
    // First call - should create initial state
    client1, err := WithRekorClient(ctx, rekorURL)
    assert.NoError(t, err)
    assert.NotNil(t, client1)
    
    // Read the stored state
    state1, err := loadRekorState()
    assert.NoError(t, err)
    assert.NotEmpty(t, state1.LastKnownState.TreeID)
    assert.True(t, state1.LastKnownState.TreeSize > 0)
    assert.NotEmpty(t, state1.LastKnownState.RootHash)
    
    // Second call - should verify consistency
    client2, err := WithRekorClient(ctx, rekorURL)
    assert.NoError(t, err)
    assert.NotNil(t, client2)
    
    // Test consistency violation by modifying state
    state1.LastKnownState.TreeSize += 1000 // Simulate impossible growth
    err = saveRekorState(state1)
    assert.NoError(t, err)
    
    _, err = WithRekorClient(ctx, rekorURL)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "tree size decreased")
}

func TestInvalidTreeID(t *testing.T) {
    tempDir := t.TempDir()
    originalHome := os.Getenv("HOME")
    os.Setenv("HOME", tempDir)
    defer os.Setenv("HOME", originalHome)
    
    ctx := context.Background()
    rekorURL := "https://rekor.sigstore.dev"
    
    // Create initial state with different tree ID
    initialState := &StoredRekorState{
        LastKnownState: RekorTreeState{
            TreeID:    "invalid-tree-id",
            TreeSize:  1,
            RootHash:  "somehash",
        },
    }
    err := saveRekorState(initialState)
    assert.NoError(t, err)
    
    _, err = WithRekorClient(ctx, rekorURL)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "tree ID mismatch")
}