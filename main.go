package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

const (
	bearerPrefix = "Bearer "
)

// Config represents the application configuration
type Config struct {
	PortainerURL          string
	PortainerUser         string
	PortainerPassword     string
	InfisicalAPIURL       string
	InfisicalToken        string
	InfisicalWorkspaceID  string
	InfisicalEnvironment  string
	LocalStacksPath       string
	EndpointID            int
	DryRun                bool
	OverrideManagedStacks bool
}

// LocalStack represents a local Docker stack configuration
type LocalStack struct {
	Name string
	Path string
}

// InfisicalResponse represents the response from Infisical API
type InfisicalResponse struct {
	Secrets []struct {
		SecretKey   string `json:"secretKey"`
		SecretValue string `json:"secretValue"`
	} `json:"secrets"`
}

// PortainerStack represents a stack in Portainer
type PortainerStack struct {
	ID          int               `json:"Id"`
	Name        string            `json:"Name"`
	Type        int               `json:"Type"`
	EndpointID  int               `json:"EndpointId"`
	SwarmID     string            `json:"SwarmId"`
	Env         []PortainerEnvVar `json:"Env"`
	Status      int               `json:"Status"`
	ProjectPath string            `json:"ProjectPath"`
	EntryPoint  string            `json:"EntryPoint"`
	GitConfig   *GitConfig        `json:"GitConfig,omitempty"`
}

// PortainerEnvVar represents an environment variable in a Portainer stack
type PortainerEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GitConfig represents Git configuration for a stack
// This is used when a stack is managed in a Git repository
type GitConfig struct {
	URL            string `json:"URL"`
	ReferenceName  string `json:"ReferenceName"`
	ConfigFilePath string `json:"ConfigFilePath"`
}

// PortainerAuth represents an authentication response from Portainer
type PortainerAuth struct {
	JWT string `json:"jwt"`
}

// PortainerAuthRequest represents an authentication request to Portainer
type PortainerAuthRequest struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}

// StackRequest represents a request to create or update a stack in Portainer
type StackRequest struct {
	Name            string            `json:"Name"`
	ComposeFile     string            `json:"StackFileContent"`
	Env             []PortainerEnvVar `json:"Env"`
	FromAppTemplate bool              `json:"FromAppTemplate"`
	AutoUpdate      bool              `json:"AutoUpdate,omitempty"`
	GitConfig       *GitConfig        `json:"GitConfig,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for StackRequest
func (s StackRequest) MarshalJSON() ([]byte, error) {
	type Alias StackRequest
	return json.Marshal(&struct {
		*Alias
		ComposeFile string `json:"StackFileContent"`
	}{
		Alias:       (*Alias)(&s),
		ComposeFile: s.ComposeFile,
	})
}

// StackDecision represents a decision made about a stack during synchronization
type StackDecision struct {
	LocalStack  *LocalStack
	RemoteStack *PortainerStack
	Action      string // "create", "update", "delete", "skip"
	Reason      string
}

// SyncReport contains the results of a synchronization operation
type SyncReport struct {
	Timestamp   time.Time
	Decisions   []StackDecision
	LocalStacks []LocalStack
	Success     int
	Failed      int
	Errors      []string
}

const (
	contentTypeJSON = "application/json"
)

// SyncClient handles synchronization between local stacks and Portainer
type SyncClient struct {
	config     Config
	httpClient *http.Client
	authToken  string
}

// NewSyncClient creates a new instance of SyncClient with the provided configuration
func NewSyncClient(config Config) *SyncClient {
	return &SyncClient{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Authenticate with Portainer
func (c *SyncClient) authenticatePortainer() error {
	authReq := PortainerAuthRequest{
		Username: c.config.PortainerUser,
		Password: c.config.PortainerPassword,
	}

	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.config.PortainerURL+"/api/auth",
		contentTypeJSON,
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var authResp PortainerAuth
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	c.authToken = authResp.JWT
	return nil
}

// fetchAllStackDirs reads all stack directories from the local stacks path
func (c *SyncClient) fetchAllStackDirs() ([]os.DirEntry, error) {
	entries, err := os.ReadDir(c.config.LocalStacksPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read local stacks directory: %w", err)
	}
	return entries, nil
}

// filterValidStackNames filters and validates stack directories
func (c *SyncClient) filterValidStackNames(entries []os.DirEntry) ([]LocalStack, error) {
	var localStacks []LocalStack
	validNameRegex := regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()

		// Filter out template and portainer directories
		if strings.ToLower(name) == "template" || strings.ToLower(name) == "portainer" || strings.ToLower(name) == "volumes" {
			continue
		}

		// Check if the directory contains a docker-compose.yml file
		stackPath := filepath.Join(c.config.LocalStacksPath, name)
		dockerComposePath := filepath.Join(stackPath, "docker-compose.yml")
		if _, err := os.Stat(dockerComposePath); os.IsNotExist(err) {
			log.Printf("Warning: No docker-compose.yml found in %s, skipping\n", stackPath)
			continue
		}

		// Validate stack name format (kebab-case with numbers)
		if !validNameRegex.MatchString(name) {
			log.Printf("Warning: Invalid stack name format '%s'. Must be kebab-case with numbers only.\n", name)
			continue
		}

		localStacks = append(localStacks, LocalStack{
			Name: name,
			Path: stackPath,
		})
	}

	return localStacks, nil
}

// readLocalStacks reads and filters local stack directories
func (c *SyncClient) readLocalStacks() ([]LocalStack, error) {
	entries, err := c.fetchAllStackDirs()
	if err != nil {
		return nil, err
	}
	return c.filterValidStackNames(entries)
}

// InfisicalSecret represents a secret from Infisical API
type InfisicalSecret struct {
	SecretKey   string `json:"secretKey"`
	SecretValue string `json:"secretValue"`
}

// fetchInfisicalSecrets makes the HTTP request to fetch secrets from Infisical for a specific stack
// stackName must be a non-empty string
func (c *SyncClient) fetchInfisicalSecrets(stackName string) ([]InfisicalSecret, error) {
	if stackName == "" {
		return nil, fmt.Errorf("stackName cannot be empty")
	}
	req, err := http.NewRequest("GET", c.config.InfisicalAPIURL+"/api/v4/secrets", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create infisical request: %w", err)
	}

	// Add query parameters
	q := req.URL.Query()
	q.Add("projectId", c.config.InfisicalWorkspaceID)
	q.Add("environment", c.config.InfisicalEnvironment)

	// Set the secret path using the stack name
	q.Add("secretPath", "/"+strings.ToLower(stackName))
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", bearerPrefix+c.config.InfisicalToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch infisical secrets: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: failed to close response body: %v", cerr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("infisical API returned status %d: %s", resp.StatusCode, string(body))
	}

	var infisicalResp struct {
		Secrets []InfisicalSecret `json:"secrets"`
	}

	if err := json.Unmarshal(body, &infisicalResp); err != nil {
		log.Printf("Failed to decode Infisical response. Raw response: %s", string(body))
		return nil, fmt.Errorf("failed to decode infisical response: %w. Response: %s", err, string(body))
	}

	log.Printf("Successfully received %d secrets from Infisical", len(infisicalResp.Secrets))
	return infisicalResp.Secrets, nil
}

// readInfisicalSecrets fetches secrets from Infisical for stacks that need to be created or updated
// Returns a map of stack names to their respective secret key-value pairs
func (c *SyncClient) readInfisicalSecrets(decisions []StackDecision) (map[string]map[string]string, error) {
	if c.config.InfisicalToken == "" || c.config.InfisicalWorkspaceID == "" {
		log.Println("Infisical configuration not provided, skipping secret fetching")
		return make(map[string]map[string]string), nil
	}

	// Create a map to store secrets for each stack
	secretsMap := make(map[string]map[string]string)

	// Track which stack names we've already processed to avoid duplicate API calls
	processedStacks := make(map[string]bool)

	// First, fetch the shared 'volumes' stack secrets if it exists
	log.Println("Fetching shared secrets from 'volumes' stack")
	volumesSecrets, err := c.fetchInfisicalSecrets("volumes")
	if err != nil {
		log.Printf("Warning: Failed to fetch shared secrets from 'volumes' stack: %v", err)
	} else {
		log.Printf("Fetched %d shared secrets from 'volumes' stack", len(volumesSecrets))
	}

	// Process each decision to find stacks that need secrets
	for _, decision := range decisions {
		// Only fetch secrets for stacks that are being created or updated
		if decision.Action != "create" && decision.Action != "update" {
			continue
		}

		// Get the stack name (should be the same in both local and remote)
		stackName := ""
		if decision.LocalStack != nil {
			stackName = decision.LocalStack.Name
		} else if decision.RemoteStack != nil {
			stackName = decision.RemoteStack.Name
		}

		// Skip if we couldn't determine the stack name, it's empty, or we've already processed it
		if stackName == "" {
			log.Printf("Warning: Could not determine stack name for decision: %+v", decision)
			continue
		}

		if processedStacks[stackName] {
			continue
		}

		processedStacks[stackName] = true
		secretsMap[stackName] = make(map[string]string)

		// Add shared volumes secrets to every stack
		for _, secret := range volumesSecrets {
			if secret.SecretKey != "" {
				secretsMap[stackName][secret.SecretKey] = secret.SecretValue
			}
		}

		// Skip fetching secrets for the 'volumes' stack itself as we already have them
		if stackName == "volumes" {
			log.Printf("Using shared secrets for stack: %s (volumes stack)", stackName)
			continue
		}

		log.Printf("Fetching stack-specific secrets for: %s", stackName)
		stackSecrets, err := c.fetchInfisicalSecrets(stackName)
		if err != nil {
			log.Printf("Warning: Failed to fetch secrets for stack %s: %v", stackName, err)
			continue
		}

		// Add stack-specific secrets (will override any shared secrets with the same key)
		for _, secret := range stackSecrets {
			if secret.SecretKey != "" {
				secretsMap[stackName][secret.SecretKey] = secret.SecretValue
			}
		}

		log.Printf("Fetched %d secrets for stack: %s (including shared secrets)", len(secretsMap[stackName]), stackName)
	}

	return secretsMap, nil
}

// Fetch stacks from Portainer
func (c *SyncClient) getPortainerStacks() ([]PortainerStack, error) {
	req, err := http.NewRequest("GET", c.config.PortainerURL+"/api/stacks", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create portainer request: %w", err)
	}

	req.Header.Set("Authorization", bearerPrefix+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch portainer stacks: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("portainer API returned status: %d", resp.StatusCode)
	}

	var stacks []PortainerStack
	if err := json.NewDecoder(resp.Body).Decode(&stacks); err != nil {
		return nil, fmt.Errorf("failed to decode portainer response: %w", err)
	}

	return stacks, nil
}

// Check if stack is managed (has GitHub label)
func (c *SyncClient) isStackManaged(stack PortainerStack) bool {
	return stack.GitConfig != nil && stack.GitConfig.URL != ""
}

// Build decision matrix
func (c *SyncClient) buildDecisionMatrix(localStacks []LocalStack, remoteStacks []PortainerStack) []StackDecision {
	var decisions []StackDecision

	// Create a map of remote stacks by name for easy lookup
	remoteStackMap := make(map[string]PortainerStack)
	for _, stack := range remoteStacks {
		remoteStackMap[stack.Name] = stack
	}

	// Check local stacks against remote
	for _, local := range localStacks {
		if remote, exists := remoteStackMap[local.Name]; exists {
			// Stack exists in both local and remote
			if c.isStackManaged(remote) {
				if c.config.OverrideManagedStacks {
					decisions = append(decisions, StackDecision{
						LocalStack:  &local,
						RemoteStack: &remote,
						Action:      "update",
						Reason:      "Overriding managed stack",
					})
				} else {
					decisions = append(decisions, StackDecision{
						LocalStack:  &local,
						RemoteStack: &remote,
						Action:      "skip",
						Reason:      "Stack is managed by Git",
					})
				}
			} else {
				decisions = append(decisions, StackDecision{
					LocalStack:  &local,
					RemoteStack: &remote,
					Action:      "update",
					Reason:      "Stack exists and needs update",
				})
			}
			delete(remoteStackMap, local.Name) // Remove from map to track remaining remote stacks
		} else {
			decisions = append(decisions, StackDecision{
				LocalStack:  &local,
				RemoteStack: nil,
				Action:      "create",
				Reason:      "New stack to create",
			})
		}
	}

	// Handle stacks that exist only remotely
	for _, remote := range remoteStackMap {
		if c.isStackManaged(remote) {
			decisions = append(decisions, StackDecision{
				LocalStack:  nil,
				RemoteStack: &remote,
				Action:      "skip",
				Reason:      "Managed stack not in local - leaving as is",
			})
		} else {
			decisions = append(decisions, StackDecision{
				LocalStack:  nil,
				RemoteStack: &remote,
				Action:      "delete",
				Reason:      "Undeclared stack - marking for deletion",
			})
		}
	}

	return decisions
}

// Create stack in Portainer
func (c *SyncClient) createStack(decision StackDecision, secrets map[string]string) error {
	composeFile, err := c.readComposeFile(decision.LocalStack.Path)
	if err != nil {
		return fmt.Errorf("failed to read compose file: %w", err)
	}

	// Validate compose file is not empty
	if strings.TrimSpace(composeFile) == "" {
		return fmt.Errorf("compose file is empty")
	}

	// Extract environment variables from compose file
	composeEnvVars, err := extractEnvVarsFromCompose(composeFile)
	if err != nil {
		log.Printf("warning: failed to extract environment variables from compose file: %v. All secrets will be included.", err)
	}
	log.Printf("Extracted environment variables from compose file: %v", composeEnvVars)

	envVars := make([]PortainerEnvVar, 0, len(secrets))
	for key, value := range secrets {
		// If we couldn't determine the environment variables from the compose file (e.g., due to env_file),
		// or if the key is in the compose file, include it
		if composeEnvVars == nil || composeEnvVars[key] {
			envVars = append(envVars, PortainerEnvVar{
				Name:  key,
				Value: value,
			})
		}
	}

	stackReq := StackRequest{
		Name:            decision.LocalStack.Name,
		ComposeFile:     composeFile,
		Env:             envVars,
		FromAppTemplate: false,
	}

	jsonData, err := json.Marshal(stackReq)
	if err != nil {
		return fmt.Errorf("failed to marshal stack request: %w", err)
	}

	// Debug: Print the request payload (commented out for production)
	// log.Printf("Creating stack request: %s", string(jsonData))

	url := fmt.Sprintf("%s/api/stacks/create/standalone/string?endpointId=%d", c.config.PortainerURL, c.config.EndpointID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create stack request: %w", err)
	}

	req.Header.Set("Authorization", bearerPrefix+c.authToken)
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create stack: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: failed to close response body: %v", cerr)
		}
	}()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to create stack '%s', status: %d, response: %s",
			decision.LocalStack.Name, resp.StatusCode, string(body))
	}

	return nil
}

// Update stack in Portainer
func (c *SyncClient) updateStack(decision StackDecision, secrets map[string]string) error {
	composeFile, err := c.readComposeFile(decision.LocalStack.Path)
	if err != nil {
		return fmt.Errorf("failed to read compose file: %w", err)
	}

	// Validate compose file is not empty
	if strings.TrimSpace(composeFile) == "" {
		return fmt.Errorf("compose file is empty")
	}

	// Extract environment variables from compose file
	composeEnvVars, err := extractEnvVarsFromCompose(composeFile)
	if err != nil {
		log.Printf("warning: failed to extract environment variables from compose file: %v. All secrets will be included.", err)
	}
	log.Printf("Extracted environment variables from compose file: %v", composeEnvVars)

	envVars := make([]PortainerEnvVar, 0, len(secrets))
	for key, value := range secrets {
		// If we couldn't determine the environment variables from the compose file (e.g., due to env_file),
		// or if the key is in the compose file, include it
		if composeEnvVars == nil || composeEnvVars[key] {
			envVars = append(envVars, PortainerEnvVar{
				Name:  key,
				Value: value,
			})
		}
	}

	stackReq := StackRequest{
		Name:        decision.RemoteStack.Name,
		ComposeFile: composeFile,
		Env:         envVars,
	}

	jsonData, err := json.Marshal(stackReq)
	if err != nil {
		return fmt.Errorf("failed to marshal stack request: %w", err)
	}

	// Debug: Print the request payload (commented out for production)
	// log.Printf("Updating stack request: %s", string(jsonData))

	url := fmt.Sprintf("%s/api/stacks/%d?endpointId=%d",
		c.config.PortainerURL, decision.RemoteStack.ID, c.config.EndpointID)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create update request: %w", err)
	}

	req.Header.Set("Authorization", bearerPrefix+c.authToken)
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update stack: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: failed to close response body: %v", cerr)
		}
	}()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to update stack '%s', status: %d, response: %s",
			decision.RemoteStack.Name, resp.StatusCode, string(body))
	}

	return nil
}

// Delete stack from Portainer
func (c *SyncClient) deleteStack(decision StackDecision) error {
	url := fmt.Sprintf("%s/api/stacks/%d?endpointId=%d",
		c.config.PortainerURL, decision.RemoteStack.ID, c.config.EndpointID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	req.Header.Set("Authorization", bearerPrefix+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete stack: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete stack, status: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// extractEnvVarsFromString extracts environment variable names from a string using ${VAR} or ${VAR:-default} syntax
func extractEnvVarsFromString(s string, envVars map[string]bool) {
	// Match ${VAR} or ${VAR:-default} patterns
	re := regexp.MustCompile(`\${([a-zA-Z_][a-zA-Z0-9_]*)(?::-[^}]*)?}`)
	matches := re.FindAllStringSubmatch(s, -1)
	for _, match := range matches {
		if len(match) > 1 {
			envVars[match[1]] = true
		}
	}
}

// extractEnvVarsFromCompose extracts environment variable names from a docker-compose file content
func extractEnvVarsFromCompose(composeContent string) (map[string]bool, error) {
	var composeConfig map[string]interface{}
	if err := yaml.Unmarshal([]byte(composeContent), &composeConfig); err != nil {
		return nil, fmt.Errorf("failed to parse compose file: %w", err)
	}

	envVars := make(map[string]bool)
	usesEnvFile := false

	// Extract environment variables from a service configuration
	extractFromService := func(serviceConfig map[string]interface{}) {
		// Handle environment variables defined as a map
		extractFromEnvMap := func(envMap map[string]interface{}) {
			for key := range envMap {
				envVars[key] = true
			}
		}

		// Handle environment variables defined as a list of "KEY=VALUE" strings
		extractFromEnvList := func(envList []interface{}) {
			for _, item := range envList {
				if envStr, isStr := item.(string); isStr {
					parts := strings.SplitN(envStr, "=", 2)
					if len(parts) > 0 && parts[0] != "" {
						envVars[parts[0]] = true
					}
				}
			}
		}

		// Process image field for environment variables
		if image, ok := serviceConfig["image"].(string); ok && image != "" {
			extractEnvVarsFromString(image, envVars)
		}

		// Process environment variables
		switch env := serviceConfig["environment"].(type) {
		case map[string]interface{}:
			extractFromEnvMap(env)
		case []interface{}:
			extractFromEnvList(env)
		}

		// Process volumes for environment variables in paths
		if volumes, ok := serviceConfig["volumes"].([]interface{}); ok {
			for _, vol := range volumes {
				if volStr, isStr := vol.(string); isStr {
					extractEnvVarsFromString(volStr, envVars)
				}
			}
		}

		// Check for env_file usage
		if envFiles, ok := serviceConfig["env_file"].([]interface{}); ok {
			for _, envFile := range envFiles {
				if envFileStr, isStr := envFile.(string); isStr && envFileStr != "" {
					extractEnvVarsFromString(envFileStr, envVars)
					usesEnvFile = true
				}
			}
		}

		// Process labels for environment variables
		if labels, ok := serviceConfig["labels"].(map[string]interface{}); ok {
			for _, value := range labels {
				if labelValue, isStr := value.(string); isStr {
					extractEnvVarsFromString(labelValue, envVars)
				}
			}
		}
	}

	// Process services if they exist
	if services, ok := composeConfig["services"].(map[string]interface{}); ok {
		for _, service := range services {
			if serviceConfig, ok := service.(map[string]interface{}); ok {
				extractFromService(serviceConfig)
			}
		}
	}

	// Process top-level environment variables (for docker-compose v2.1+)
	switch env := composeConfig["environment"].(type) {
	case map[string]interface{}:
		for key := range env {
			envVars[key] = true
		}
	}

	// If the compose file uses env_file, we can't determine which variables are actually used
	if usesEnvFile {
		return nil, nil
	}

	return envVars, nil
}

// Read compose file content
func (c *SyncClient) readComposeFile(stackPath string) (string, error) {
	var composeFile string
	for _, filename := range []string{"docker-compose.yml", "docker-compose.yaml"} {
		filePath := filepath.Join(stackPath, filename)
		if _, err := os.Stat(filePath); err == nil {
			composeFile = filePath
			break
		}
	}

	if composeFile == "" {
		return "", fmt.Errorf("no docker-compose file found in %s", stackPath)
	}

	content, err := os.ReadFile(composeFile)
	if err != nil {
		return "", fmt.Errorf("failed to read compose file %s: %w", composeFile, err)
	}

	return string(content), nil
}

// Apply changes based on decision matrix
func (c *SyncClient) applyChanges(decisions []StackDecision, secretsMap map[string]map[string]string) *SyncReport {
	report := &SyncReport{
		Timestamp: time.Now(),
		Decisions: decisions,
	}

	dryRun := c.config.DryRun
	if dryRun {
		log.Println("[DRY RUN] No actual changes will be made to Portainer")
	}

	for i := range decisions {
		decision := &decisions[i]
		var stackSecrets map[string]string

		if decision.LocalStack != nil {
			if secrets, exists := secretsMap[decision.LocalStack.Name]; exists {
				stackSecrets = secrets
			} else {
				stackSecrets = make(map[string]string)
			}

			if dryRun {
				log.Printf("[DRY RUN] Would process stack: %s (Action: %s, Reason: %s)",
					decision.LocalStack.Name, decision.Action, decision.Reason)
				if len(stackSecrets) > 0 {
					log.Printf("[DRY RUN] Would apply %d secrets to stack %s",
						len(stackSecrets), decision.LocalStack.Name)
				}
				continue
			}
		}

		switch decision.Action {
		case "create":
			if dryRun {
				log.Printf("[DRY RUN] Would create stack: %s", decision.LocalStack.Name)
				report.Success++
				continue
			}

			err := c.createStack(*decision, stackSecrets)
			if err != nil {
				report.Failed++
				report.Errors = append(report.Errors,
					fmt.Sprintf("Failed to create stack %s: %v", decision.LocalStack.Name, err))
				log.Printf("Failed to create stack %s: %v", decision.LocalStack.Name, err)
			} else {
				report.Success++
				log.Printf("Successfully created stack: %s", decision.LocalStack.Name)
			}

		case "update":
			if dryRun {
				log.Printf("[DRY RUN] Would update stack: %s", decision.LocalStack.Name)
				report.Success++
				continue
			}

			err := c.updateStack(*decision, stackSecrets)
			if err != nil {
				report.Failed++
				report.Errors = append(report.Errors,
					fmt.Sprintf("Failed to update stack %s: %v", decision.LocalStack.Name, err))
				log.Printf("Failed to update stack %s: %v", decision.LocalStack.Name, err)
			} else {
				report.Success++
				log.Printf("Successfully updated stack: %s", decision.LocalStack.Name)
			}

		case "delete":
			if dryRun {
				log.Printf("[DRY RUN] Would delete stack: %s", decision.RemoteStack.Name)
				report.Success++
				continue
			}

			err := c.deleteStack(*decision)
			if err != nil {
				report.Failed++
				report.Errors = append(report.Errors,
					fmt.Sprintf("Failed to delete stack %s: %v", decision.RemoteStack.Name, err))
				log.Printf("Failed to delete stack %s: %v", decision.RemoteStack.Name, err)
			} else {
				report.Success++
				log.Printf("Successfully deleted stack: %s", decision.RemoteStack.Name)
			}

		case "skip":
			// Skip silently
		}
	}

	return report
}

// Generate and print report
func (c *SyncClient) generateReport(report *SyncReport, localStacks []LocalStack) {
	report.LocalStacks = localStacks

	// Create a buffer to build the markdown report
	var reportContent bytes.Buffer

	// Write the report header
	reportContent.WriteString("## Portainer Stack Changes Report\n\n")
	reportContent.WriteString(fmt.Sprintf("**Execution Mode:** %s\n\n", func() string {
		if c.config.DryRun {
			return "DRY RUN"
		}
		return "LIVE"
	}()))

	// Initialize counters and stacks lists
	var added, updated, deleted int
	var addedStacks, updatedStacks, deletedStacks []string

	// Process decisions
	for _, decision := range report.Decisions {
		stackName := ""
		if decision.LocalStack != nil {
			stackName = decision.LocalStack.Name
		} else if decision.RemoteStack != nil {
			stackName = decision.RemoteStack.Name
		}

		switch decision.Action {
		case "create":
			added++
			addedStacks = append(addedStacks, fmt.Sprintf("%s (%s)", stackName, decision.Reason))
		case "update":
			updated++
			updatedStacks = append(updatedStacks, fmt.Sprintf("%s (%s)", stackName, decision.Reason))
		case "delete":
			deleted++
			deletedStacks = append(deletedStacks, fmt.Sprintf("%s (%s)", stackName, decision.Reason))
		}
	}

	// Write the summary table
	reportContent.WriteString("| Action | Count | Details |\n")
	reportContent.WriteString("|--------|-------|---------|\n")

	// Added stacks
	if added > 0 {
		reportContent.WriteString(fmt.Sprintf("| ➕ Added | %d | New stacks created |\n", added))
		for _, stack := range addedStacks {
			reportContent.WriteString(fmt.Sprintf("| | | - %s |\n", stack))
		}
	} else {
		reportContent.WriteString("| ➕ Added | 0 | No new stacks |\n")
	}

	// Updated stacks
	if updated > 0 {
		reportContent.WriteString(fmt.Sprintf("| 🔄 Updated | %d | Existing stacks updated |\n", updated))
		for _, stack := range updatedStacks {
			reportContent.WriteString(fmt.Sprintf("| | | - %s |\n", stack))
		}
	} else {
		reportContent.WriteString("| 🔄 Updated | 0 | No stacks updated |\n")
	}

	// Deleted stacks
	if deleted > 0 {
		reportContent.WriteString(fmt.Sprintf("| 🗑️ Deleted | %d | Stacks removed |\n", deleted))
		for _, stack := range deletedStacks {
			reportContent.WriteString(fmt.Sprintf("| | | - %s |\n", stack))
		}
	} else {
		reportContent.WriteString("| 🗑️ Deleted | 0 | No stacks deleted |\n")
	}

	// Write the report to a file
	reportFile := "stack-changes-report.md"
	err := os.WriteFile(reportFile, reportContent.Bytes(), 0644)
	if err != nil {
		fmt.Printf("Error writing report file: %v\n", err)
	} else {
		fmt.Printf("\nReport generated: %s\n", reportFile)
	}

	// Also print a summary to console
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("PORTAINER STACK SYNCHRONIZATION SUMMARY")
	fmt.Printf("Generated: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\nTOTAL ACTIONS:\n")
	fmt.Printf("- Added:   %d\n", added)
	fmt.Printf("- Updated: %d\n", updated)
	fmt.Printf("- Deleted: %d\n", deleted)

	if len(report.Errors) > 0 {
		fmt.Printf("\nERRORS OCCURRED:\n")
		for _, err := range report.Errors {
			fmt.Printf("- %s\n", err)
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
}

// Sync performs the synchronization between local stacks and Portainer
// It reads local stacks, fetches remote stacks, makes decisions, and applies changes
func (c *SyncClient) Sync() error {
	// Step 1: Authenticate with Portainer
	log.Println("Authenticating with Portainer...")
	if err := c.authenticatePortainer(); err != nil {
		return fmt.Errorf("failed to authenticate with Portainer: %w", err)
	}

	// Step 2: Read local directories
	log.Println("Reading local stack directories...")
	localStacks, err := c.readLocalStacks()
	if err != nil {
		return fmt.Errorf("failed to read local stacks: %w", err)
	}
	log.Printf("Found %d local stacks", len(localStacks))
	for i, stack := range localStacks {
		log.Printf("  [%d] %s (path: %s)", i+1, stack.Name, stack.Path)
	}

	// Step 3: Get Portainer stacks
	log.Println("Fetching stacks from Portainer...")
	remoteStacks, err := c.getPortainerStacks()
	if err != nil {
		return fmt.Errorf("failed to fetch Portainer stacks: %w", err)
	}
	log.Printf("Found %d remote stacks", len(remoteStacks))

	// Step 4: Build decision matrix
	log.Println("Building decision matrix...")
	decisions := c.buildDecisionMatrix(localStacks, remoteStacks)
	log.Printf("Generated %d decisions", len(decisions))

	// Step 5: Read secrets from Infisical for stacks that need to be created or updated
	log.Println("Reading secrets from Infisical for stacks that need updates...")
	secretsMap, err := c.readInfisicalSecrets(decisions)
	if err != nil {
		return fmt.Errorf("failed to read Infisical secrets: %w", err)
	}
	log.Printf("Found secrets for %d stacks", len(secretsMap))

	// Step 6: Apply changes
	log.Println("Applying changes...")
	report := c.applyChanges(decisions, secretsMap)

	// Step 7: Generate report
	c.generateReport(report, localStacks)

	return nil
}

// Load configuration from environment variables
func loadConfig() Config {
	_ = godotenv.Load() // Load .env file if it exists

	return Config{
		PortainerURL:          getEnvOrDefault("PORTAINER_URL", "http://localhost:9000"),
		PortainerUser:         getEnvOrDefault("PORTAINER_USER", "admin"),
		PortainerPassword:     getEnvOrDefault("PORTAINER_PASSWORD", ""),
		InfisicalAPIURL:       getEnvOrDefault("INFISICAL_API_URL", "https://app.infisical.com"),
		InfisicalToken:        getEnvOrDefault("INFISICAL_TOKEN", ""),
		InfisicalWorkspaceID:  getEnvOrDefault("INFISICAL_WORKSPACE_ID", ""),
		InfisicalEnvironment:  getEnvOrDefault("INFISICAL_ENVIRONMENT", "prod"),
		LocalStacksPath:       getEnvOrDefault("LOCAL_STACKS_PATH", "./stacks"),
		EndpointID:            getEnvIntOrDefault("PORTAINER_ENDPOINT_ID", 1),
		DryRun:                getEnvOrDefault("DRY_RUN", "false") == "true",
		OverrideManagedStacks: getEnvOrDefault("OVERRIDE_MANAGED_STACKS", "false") == "true",
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue := parseInt(value); intValue != 0 {
			return intValue
		}
	}
	return defaultValue
}

func parseInt(s string) int {
	var result int
	if _, err := fmt.Sscanf(s, "%d", &result); err != nil {
		log.Printf("warning: failed to parse int from %q: %v", s, err)
	}
	return result
}

func main() {
	log.Println("Starting Portainer Stack Synchronizer...")

	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found or error loading it: %v", err)
		log.Println("Continuing with environment variables...")
	} else {
		log.Println("Loaded configuration from .env file")
	}

	config := loadConfig()

	// Validate required configuration
	if config.PortainerPassword == "" {
		log.Fatal("PORTAINER_PASSWORD environment variable is required")
	}
	if config.InfisicalToken == "" {
		log.Fatal("INFISICAL_TOKEN environment variable is required")
	}

	client := NewSyncClient(config)

	if err := client.Sync(); err != nil {
		log.Fatalf("Synchronization failed: %v", err)
	}

	log.Println("Synchronization completed successfully!")
}
