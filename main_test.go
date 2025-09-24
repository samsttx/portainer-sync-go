package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testComposeFile       = "docker-compose.yml"
	newStackName          = "new-stack"
	existingStackName     = "existing-stack"
	managedStackName      = "managed-stack"
	undeclaredStackName   = "undeclared-stack"
	managedOnlyRemoteName = "managed-only-remote"
	gitRepoURL            = "https://github.com/user/repo.git"
	swarmID               = "swarm1"
)

func TestBuildDecisionMatrix(t *testing.T) {
	tests := []struct {
		name           string
		localStacks    []LocalStack
		remoteStacks   []PortainerStack
		config         Config
		expectedAction string // The action we expect for the first decision (for simplicity)
		expectedReason string // The reason we expect for the first decision
	}{
		{
			name: "New stack should be created",
			localStacks: []LocalStack{
				{Name: newStackName, Path: testComposeFile},
			},
			remoteStacks:   []PortainerStack{},
			config:         Config{OverrideManagedStacks: false},
			expectedAction: "create",
			expectedReason: "New stack to create",
		},
		{
			name: "Existing stack should be updated",
			localStacks: []LocalStack{
				{Name: existingStackName, Path: testComposeFile},
			},
			remoteStacks: []PortainerStack{
				{ID: 1, Name: existingStackName, SwarmID: swarmID},
			},
			config:         Config{OverrideManagedStacks: false},
			expectedAction: "update",
			expectedReason: "Stack exists and needs update",
		},
		{
			name: "Managed stack should be skipped by default",
			localStacks: []LocalStack{
				{Name: managedStackName, Path: testComposeFile},
			},
			remoteStacks: []PortainerStack{
				{ID: 2, Name: managedStackName, SwarmID: swarmID, GitConfig: &GitConfig{
					URL: gitRepoURL,
				}},
			},
			config:         Config{OverrideManagedStacks: false},
			expectedAction: "skip",
			expectedReason: "Stack is managed by Git",
		},
		{
			name: "Managed stack should be updated when override is true",
			localStacks: []LocalStack{
				{Name: managedStackName, Path: testComposeFile},
			},
			remoteStacks: []PortainerStack{
				{ID: 3, Name: managedStackName, SwarmID: swarmID, GitConfig: &GitConfig{
					URL: gitRepoURL,
				}},
			},
			config:         Config{OverrideManagedStacks: true},
			expectedAction: "update",
			expectedReason: "Overriding managed stack",
		},
		{
			name:        "Undeclared stack should be deleted",
			localStacks: []LocalStack{},
			remoteStacks: []PortainerStack{
				{ID: 4, Name: undeclaredStackName, SwarmID: swarmID},
			},
			config:         Config{OverrideManagedStacks: false},
			expectedAction: "delete",
			expectedReason: "Undeclared stack - marking for deletion",
		},
		{
			name:        "Managed stack not in local should be skipped",
			localStacks: []LocalStack{},
			remoteStacks: []PortainerStack{
				{ID: 5, Name: managedOnlyRemoteName, SwarmID: swarmID, GitConfig: &GitConfig{
					URL: gitRepoURL,
				}},
			},
			config:         Config{OverrideManagedStacks: false},
			expectedAction: "skip",
			expectedReason: "Managed stack not in local - leaving as is",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &SyncClient{
				config: tt.config,
			}

			decisions := client.buildDecisionMatrix(tt.localStacks, tt.remoteStacks)

			// For simplicity, we're just checking the first decision
			// In a real test, you might want to check all decisions
			if len(decisions) == 0 {
				t.Fatal("No decisions were made")
			}

			assert.Equal(t, tt.expectedAction, decisions[0].Action, "Unexpected action")
			assert.Equal(t, tt.expectedReason, decisions[0].Reason, "Unexpected reason")

			// Additional assertions based on the action
			switch decisions[0].Action {
			case "create":
				assert.NotNil(t, decisions[0].LocalStack, "LocalStack should not be nil for create action")
				assert.Nil(t, decisions[0].RemoteStack, "RemoteStack should be nil for create action")
			case "update":
				assert.NotNil(t, decisions[0].LocalStack, "LocalStack should not be nil for update action")
				assert.NotNil(t, decisions[0].RemoteStack, "RemoteStack should not be nil for update action")
			case "delete":
				assert.Nil(t, decisions[0].LocalStack, "LocalStack should be nil for delete action")
				assert.NotNil(t, decisions[0].RemoteStack, "RemoteStack should not be nil for delete action")
			case "skip":
				// For skip, either LocalStack or RemoteStack could be nil depending on the scenario
				if decisions[0].LocalStack == nil {
					assert.NotNil(t, decisions[0].RemoteStack, "For skip with no LocalStack, RemoteStack should not be nil")
				} else if decisions[0].RemoteStack == nil {
					t.Fatal("Unexpected: LocalStack exists but RemoteStack is nil for skip action")
				}
			}
		})
	}
}

func TestFilterValidStackNames(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(t *testing.T, tempDir string) []os.DirEntry
		expectedStacks []LocalStack
		expectError    bool
	}{
		{
			name: "valid stack directories",
			setup: func(t *testing.T, tempDir string) []os.DirEntry {
				// Create valid stack directories
				createStackDir(t, tempDir, "my-stack-1")
				createStackDir(t, tempDir, "my-stack-2")

				entries, err := os.ReadDir(tempDir)
				require.NoError(t, err)
				return entries
			},
			expectedStacks: []LocalStack{
				{Name: "my-stack-1", Path: filepath.Join(os.TempDir(), "portainer-test", "my-stack-1")},
				{Name: "my-stack-2", Path: filepath.Join(os.TempDir(), "portainer-test", "my-stack-2")},
			},
		},
		{
			name: "filter out template and portainer directories",
			setup: func(t *testing.T, tempDir string) []os.DirEntry {
				// Create valid and special directories
				createStackDir(t, tempDir, "valid-stack")
				createStackDir(t, tempDir, "template")
				createStackDir(t, tempDir, "Portainer") // Test case insensitivity

				entries, err := os.ReadDir(tempDir)
				require.NoError(t, err)
				return entries
			},
			expectedStacks: []LocalStack{
				{Name: "valid-stack", Path: filepath.Join(os.TempDir(), "portainer-test", "valid-stack")},
			},
		},
		{
			name: "filter out invalid stack names",
			setup: func(t *testing.T, tempDir string) []os.DirEntry {
				// Create directories with invalid names
				createStackDir(t, tempDir, "valid-stack")
				createStackDir(t, tempDir, "invalid_stack")      // Underscore not allowed
				createStackDir(t, tempDir, "Uppercase-Stack")    // Uppercase not allowed
				createStackDir(t, tempDir, "stack-with-$ymbols") // Special characters not allowed

				entries, err := os.ReadDir(tempDir)
				require.NoError(t, err)
				return entries
			},
			expectedStacks: []LocalStack{
				{Name: "valid-stack", Path: filepath.Join(os.TempDir(), "portainer-test", "valid-stack")},
			},
		},
		{
			name: "filter out non-directory entries",
			setup: func(t *testing.T, tempDir string) []os.DirEntry {
				// Create a valid stack directory and a file
				createStackDir(t, tempDir, "valid-stack")
				file, err := os.Create(filepath.Join(tempDir, "not-a-directory"))
				require.NoError(t, err)
				require.NoError(t, file.Close())

				entries, err := os.ReadDir(tempDir)
				require.NoError(t, err)
				return entries
			},
			expectedStacks: []LocalStack{
				{Name: "valid-stack", Path: filepath.Join(os.TempDir(), "portainer-test", "valid-stack")},
			},
		},
		{
			name: "empty directory",
			setup: func(t *testing.T, tempDir string) []os.DirEntry {
				entries, err := os.ReadDir(tempDir)
				require.NoError(t, err)
				return entries
			},
			expectedStacks: []LocalStack{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for testing
			tempDir, err := os.MkdirTemp("", "portainer-test")
			require.NoError(t, err)
			t.Cleanup(func() {
				if err := os.RemoveAll(tempDir); err != nil {
					// Fail the test if cleanup fails to ensure error is accounted for
					t.Fatalf("failed to cleanup temp dir %s: %v", tempDir, err)
				}
			})

			// Set up the test case
			entries := tt.setup(t, tempDir)

			// Create a test client with the temp directory as LocalStacksPath
			client := &SyncClient{
				config: Config{
					LocalStacksPath: tempDir,
				},
			}

			// Call the function under test
			result, err := client.filterValidStackNames(entries)

			// Verify the results
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Normalize paths in expected results to handle temp dir differences
			expected := make([]LocalStack, len(tt.expectedStacks))
			for i, stack := range tt.expectedStacks {
				expected[i] = LocalStack{
					Name: stack.Name,
					Path: filepath.Join(tempDir, stack.Name),
				}
			}

			assert.ElementsMatch(t, expected, result)
		})
	}
}

// createStackDir is a helper function to create a stack directory with a docker-compose.yml file
func createStackDir(t *testing.T, parentDir, name string) {
	dirPath := filepath.Join(parentDir, name)
	err := os.MkdirAll(dirPath, 0755)
	require.NoError(t, err)

	// Create a minimal docker-compose.yml file
	composePath := filepath.Join(dirPath, "docker-compose.yml")
	err = os.WriteFile(composePath, []byte("version: '3'"), 0644)
	require.NoError(t, err, "Failed to create docker-compose.yml file")
}

func TestExtractEnvVarsFromCompose(t *testing.T) {
	tests := []struct {
		name        string
		composeYAML string
		expected    map[string]bool
		expectError bool
	}{
		{
			name: "Environment variables as map",
			composeYAML: `version: '3'
services:
  web:
    image: nginx:latest
    environment:
      DB_HOST: db
      DB_PORT: 5432
      DEBUG: "true"`,
			expected: map[string]bool{
				"DB_HOST": true,
				"DB_PORT": true,
				"DEBUG":   true,
			},
			expectError: false,
		},
		{
			name: "Environment variables as list",
			composeYAML: `version: '3'
services:
  app:
    image: myapp:latest
    environment:
      - DB_USER=admin
      - DB_PASS=secret
      - LOG_LEVEL=debug`,
			expected: map[string]bool{
				"DB_USER":   true,
				"DB_PASS":   true,
				"LOG_LEVEL": true,
			},
			expectError: false,
		},
		{
			name: "With env_file usage",
			composeYAML: `version: '3'
services:
  worker:
    image: worker:latest
    env_file:
      - .env
    environment:
      - WORKER_COUNT=3`,
			expected:    nil, // Should return nil when env_file is used
			expectError: false,
		},
		{
			name: "Top-level environment variables",
			composeYAML: `version: '3'
services:
  web:
    image: nginx:alpine

environment:
  GLOBAL_VAR: value
  ANOTHER_VAR: 123`,
			expected: map[string]bool{
				"GLOBAL_VAR":  true,
				"ANOTHER_VAR": true,
			},
			expectError: false,
		},
		{
			name:        "Invalid YAML",
			composeYAML: `invalid: yaml: :1:1: did not find expected node content`,
			expected:    nil,
			expectError: true,
		},
		{
			name: "Environment variables in volume paths",
			composeYAML: `version: '3'
services:
  app:
    image: myapp:latest
    volumes:
      - cache:/cache
      - config:/config
      - ${DATA_MOVIES}:/movies
      - ${DATA_TVSHOWS}:/tvshows
      - /host/path:${CONTAINER_PATH}
      - ${HOST_PATH}:${CONTAINER_PATH}:ro`,
			expected: map[string]bool{
				"DATA_MOVIES":    true,
				"DATA_TVSHOWS":   true,
				"CONTAINER_PATH": true,
				"HOST_PATH":      true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractEnvVarsFromCompose(tt.composeYAML)

			if tt.expectError {
				assert.Error(t, err, "Expected an error but got none")
				return
			}

			require.NoError(t, err, "Unexpected error")

			if tt.expected == nil {
				assert.Nil(t, result, "Expected nil result")
				return
			}

			assert.Equal(t, len(tt.expected), len(result), "Unexpected number of environment variables")

			for key := range tt.expected {
				_, exists := result[key]
				assert.True(t, exists, "Expected environment variable not found: %s", key)
			}
		})
	}
}
