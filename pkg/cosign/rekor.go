
package cosign

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "io/ioutil"
    "os"
    "path/filepath"
    
    "github.com/go-openapi/runtime"
    rclient "github.com/sigstore/rekor/pkg/client"
    "github.com/sigstore/rekor/pkg/generated/client"
    "github.com/sigstore/rekor/pkg/generated/client/index"
    "github.com/sigstore/rekor/pkg/generated/models"
)

// Add these structs for state tracking
type RekorTreeState struct {
    TreeID       string `json:"treeId"`
    TreeSize     int64  `json:"treeSize"`
    RootHash     string `json:"rootHash"`
    Timestamp    int64  `json:"timestamp"`
    Signature    string `json:"signature"`
}

type StoredRekorState struct {
    LastKnownState RekorTreeState `json:"lastKnownState"`
}

// Add configuration constants
const (
    rekorStateFile = ".cosign/rekor_state.json"
)

// Add helper functions
func getStateFilePath() (string, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return "", err
    }
    return filepath.Join(home, rekorStateFile), nil
}

func loadRekorState() (*StoredRekorState, error) {
    stateFile, err := getStateFilePath()
    if err != nil {
        return nil, err
    }
    
    if _, err := os.Stat(stateFile); os.IsNotExist(err) {
        return &StoredRekorState{}, nil
    }
    
    data, err := ioutil.ReadFile(stateFile)
    if err != nil {
        return nil, err
    }
    
    var state StoredRekorState
    if err := json.Unmarshal(data, &state); err != nil {
        return nil, err
    }
    return &state, nil
}

func saveRekorState(state *StoredRekorState) error {
    stateFile, err := getStateFilePath()
    if err != nil {
        return err
    }
    
    if err := os.MkdirAll(filepath.Dir(stateFile), 0700); err != nil {
        return err
    }
    
    data, err := json.MarshalIndent(state, "", "  ")
    if err != nil {
        return err
    }
    
    return ioutil.WriteFile(stateFile, data, 0600)
}

func getCurrentTreeState(rekorClient *client.Rekor) (*RekorTreeState, error) {
    params := index.NewGetIndexParams()
    resp, err := rekorClient.Index.GetIndex(params, runtime.ClientAuthInfoWriterFunc(func(r runtime.ClientRequest, _ strfmt.Registry) error {
        return nil
    }))
    if err != nil {
        return nil, err
    }
    
    logInfo := resp.Payload
    rootHashBytes := sha256.Sum256([]byte(logInfo.RootHash))
    rootHash := hex.EncodeToString(rootHashBytes[:])
    
    return &RekorTreeState{
        TreeID:    logInfo.TreeID,
        TreeSize:  logInfo.TreeSize,
        RootHash:  rootHash,
        Timestamp: logInfo.SignedTreeHead.Timestamp,
        Signature: string(logInfo.SignedTreeHead.Signature),
    }, nil
}

func verifyTreeConsistency(prevState, currState *RekorTreeState) error {
    if prevState.TreeID == "" {
        // First time seeing this tree, no consistency check needed
        return nil
    }
    
    if prevState.TreeID != currState.TreeID {
        return fmt.Errorf("tree ID mismatch: previous %s, current %s", prevState.TreeID, currState.TreeID)
    }
    
    if prevState.TreeSize > currState.TreeSize {
        return fmt.Errorf("tree size decreased: previous %d, current %d", prevState.TreeSize, currState.TreeSize)
    }
    
    if prevState.RootHash != currState.RootHash && prevState.TreeSize == currState.TreeSize {
        return fmt.Errorf("root hash changed for same tree size: previous %s, current %s", 
            prevState.RootHash, currState.RootHash)
    }
    
    return nil
}

// Modify your existing Rekor interaction function to include state tracking
func WithRekorClient(ctx context.Context, rekorURL string) (*client.Rekor, error) {
    rekorClient, err := rclient.GetRekorClient(rekorURL)
    if err != nil {
        return nil, err
    }
    
    // Load previous state
    prevState, err := loadRekorState()
    if err != nil {
        return nil, fmt.Errorf("failed to load rekor state: %v", err)
    }
    
    // Get current state
    currState, err := getCurrentTreeState(rekorClient)
    if err != nil {
        return nil, fmt.Errorf("failed to get current rekor state: %v", err)
    }
    
    // Verify consistency
    if err := verifyTreeConsistency(&prevState.LastKnownState, currState); err != nil {
        return nil, fmt.Errorf("rekor tree consistency check failed: %v", err)
    }
    
    // Update stored state
    newState := StoredRekorState{
        LastKnownState: *currState,
    }
    if err := saveRekorState(&newState); err != nil {
        return nil, fmt.Errorf("failed to save rekor state: %v", err)
    }
    
    return rekorClient, nil
}