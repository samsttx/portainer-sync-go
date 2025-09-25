# Portainer Sync

A Go application that synchronizes Docker Compose stacks between a local directory and a Portainer instance, with support for secret management via Infisical.

## TODO

- improve env var check in compose file
- in reports log status of create / delete / update
- do not update if not changes
- deploy single stack or list
- apply only specific action
- report 1: numbers per action
- report 2: list stacks table with name, actions,   status(success/error), reason, env vars count and names

## Features

- Synchronizes local Docker Compose stacks with a Portainer instance
- Supports environment variable management through Infisical
- Dry-run mode to preview changes before applying them
- Detailed reporting of synchronization actions
- Filtering of managed and unmanaged stacks

## How It Works

The application performs the following main operations:

1. **Authentication**: Authenticates with the Portainer API using provided credentials
2. **Local Stack Discovery**: Scans the configured local directory for Docker Compose stacks
3. **Remote Stack Fetching**: Retrieves the list of existing stacks from Portainer
4. **Decision Making**: Compares local and remote stacks to determine required actions (create/update/delete)
5. **Secret Management**: Fetches environment-specific secrets from Infisical
6. **Synchronization**: Applies changes to the Portainer instance based on the decision matrix
7. **Reporting**: Generates a detailed report of all actions taken

## Prerequisites

- Go 1.16 or higher
- Portainer instance with API access
- (Optional) Infisical account for secret management
- Environment variables configured (see `.env.example`)

## Development

### First-time Setup

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd portainer-sync-go
   ```

2. Install Go dependencies:

   ```bash
   go mod download
   ```

3. Enable the Git pre-commit hook for this repository:

   ```bash
   git config core.hooksPath .githooks
   chmod +x .githooks/pre-commit
   ```

   The pre-commit hook will run formatting checks, `go vet`, optional linting via `golangci-lint` (if installed), and `go test` on each commit.

   Optional: install `golangci-lint` so the lint step runs locally:

   ```bash
   brew install golangci-lint
   # or see https://golangci-lint.run/usage/install/
   ```

4. Install test dependencies:

   ```bash
   go get github.com/stretchr/testify/assert
   ```

5. Copy the example environment file and update with your configuration:

   ```bash
   cp .env.example .env
   ```

6. Edit the `.env` file with your Portainer and Infisical credentials

### Running Tests

To run all tests:

```bash
go test -v ./...
```

To run a specific test:

```bash
go test -v -run TestBuildDecisionMatrix
```

To run tests with coverage:

```bash
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

### Build

To build the application:

```bash
go build -o portainer-sync
```

### Run

To run the application:

```bash
# Run directly
PORT=8080 go run .
# Or run the built binary
./portainer-sync
```

### Configuration

The application is configured through environment variables. See `.env.example` for all available options.

## TODO

- [ ] Split into multiple files for better organization
- [x] Add tests for buildDecisionMatrix
- [x] Add tests for remaining components
  - [x] Split into 2 methods readInfisicalSecrets -> fetch avec filter add tests for filter
  - [x] Split into 2 methods readLocalStacks -> fetch avec filter add tests for filter
- [x] Add CI/CD pipeline for GitHub Actions
  - [x] Build project
  - [x] Run tests
  - [x] Run linter
  - [x] Handle versioning and tag automatically
  - [x] Push binary to GitHub releases
- [ ] Run a code review

## License

[MIT](LICENSE)
