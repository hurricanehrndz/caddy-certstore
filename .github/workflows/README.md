# GitHub Actions Workflows

This directory contains CI/CD workflows for the caddy-certstore project.

## Workflows

### 🧪 test.yml - Comprehensive Testing
**Triggers:** Push to main/master/develop, Pull Requests, Manual

Tests the module across multiple platforms using Go version from `.go-version`:

- **Linux (Ubuntu)**: Unit tests only
- **macOS**: Full integration tests with Keychain
- **Windows**: Full integration tests with Certificate Store

**Coverage**: Results uploaded to Codecov with platform-specific flags.

### 🔍 pr.yml - Pull Request Checks
**Triggers:** Pull Request events (opened, synchronize, reopened)

Fast validation for pull requests with 4 jobs:

- **Quick Test**: Unit tests on Linux
- **Code Quality**: Runs `make lint` and `make format` checks
- **macOS Integration**: Full integration tests
- **Windows Integration**: Full integration tests

**All quality checks run on every PR** to catch issues early.

### 📦 release.yml - Release Automation
**Triggers:** Git tags (v*), Manual

Handles the release process:

1. Runs full test suite (`test.yml`)
2. Runs code quality checks (`quality.yml`)
3. Generates changelog
4. Creates GitHub release with notes
5. Optional Discord notifications

**Tag Format**: `v0.1.0`, `v1.0.0-beta.1`, etc.

### ✨ quality.yml - Code Quality
**Triggers:** Push to main/master/develop, Pull Requests, Weekly schedule

Comprehensive code quality checks:

- **Lint**: Runs `make lint` (includes golangci-lint and govulncheck)
- **Format**: Runs `make format` and checks for uncommitted changes
- **Dependencies**: Checks for outdated packages and verifies go.mod/go.sum
- **Coverage**: 30% minimum threshold with Codecov upload

**All checks run on PRs** to ensure code quality before merge.

## Key Features

### 🎯 Go Version Management

All workflows use the Go version specified in `.go-version`:

```yaml
- name: Set up Go
  uses: actions/setup-go@v5
  with:
    go-version-file: '.go-version'
    cache: true
```

This ensures consistency across all CI/CD environments and matches local development.

### 🔧 Makefile Integration

Workflows use Makefile commands for consistency:

```bash
make lint     # Runs golangci-lint + govulncheck
make format   # Formats code
make test     # Runs tests
```

**Tools are installed via `tools.mod`:**
```bash
go mod download -modfile=tools.mod
```

### 🚀 Pull Request Workflow

PRs trigger **4 parallel jobs**:

1. ✅ **Quick Test** (Linux) - Unit tests (~2 min)
2. ✅ **Code Quality** - Linting + Formatting checks (~3 min)
3. ✅ **macOS Integration** - Full integration tests (~5 min)
4. ✅ **Windows Integration** - Full integration tests (~6 min)

**Total PR validation time: ~6 minutes** (parallel execution)

### 📊 Platform Support

| Platform | Test Type | Store Type | Duration |
|----------|-----------|------------|----------|
| Linux    | Unit      | N/A        | ~2 min   |
| macOS    | Integration | Keychain | ~5 min   |
| Windows  | Integration | CertStore | ~6 min   |

## Workflow Status Badges

Add these to your README.md:

```markdown
[![Tests](https://github.com/hurricanehrndz/caddy-certstore/workflows/Tests/badge.svg)](https://github.com/hurricanehrndz/caddy-certstore/actions?query=workflow%3ATests)
[![Code Quality](https://github.com/hurricanehrndz/caddy-certstore/workflows/Code%20Quality/badge.svg)](https://github.com/hurricanehrndz/caddy-certstore/actions?query=workflow%3A%22Code+Quality%22)
[![codecov](https://codecov.io/gh/hurricanehrndz/caddy-certstore/branch/main/graph/badge.svg)](https://codecov.io/gh/hurricanehrndz/caddy-certstore)
```

## Secrets Configuration

Configure these secrets in your GitHub repository settings:

### Optional Secrets

- **`CODECOV_TOKEN`**: For private repositories (public repos work without it)
- **`DISCORD_WEBHOOK`**: For release notifications to Discord

### How to Add Secrets

1. Go to repository Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Add name and value

## Environment Variables

Workflows use these environment variables to control test execution:

- **`SKIP_KEYCHAIN_TESTS=1`**: Skip macOS keychain integration tests
- **`SKIP_CERTSTORE_TESTS=1`**: Skip Windows certificate store integration tests

Both are set on Linux to run unit tests only.

## Local Testing

Test workflows locally using [act](https://github.com/nektos/act):

```bash
# Install act
brew install act  # macOS

# Run PR workflow
act pull_request

# Run specific job
act -j quick-test

# Run with secrets
act -s CODECOV_TOKEN=your-token
```

## Makefile Commands

Workflows leverage these Makefile targets:

### `make lint`
Runs linting and security checks:
- `golangci-lint run` - Comprehensive linting
- `govulncheck ./...` - Vulnerability scanning

### `make format`
Formats code using:
- `golangci-lint fmt` - Code formatting

### `make test`
Runs all tests:
- `go test -v ./...`

## Customization

### Changing Go Version

Update `.go-version` file:
```bash
echo "1.25.3" > .go-version
```

All workflows will automatically use this version.

### Adjusting Coverage Threshold

Edit `quality.yml`:
```bash
if (( $(echo "$COVERAGE < 30.0" | bc -l) )); then
```

### Modifying Linter Settings

Edit `.golangci.yml` in the repository root, or update the `make lint` target in `Makefile`.

## Troubleshooting

### Tests Fail on Windows/macOS But Pass Locally

- Ensure test certificates in `testdata/` are committed
- Check that certificate import doesn't require user interaction
- Verify cleanup happens in deferred functions

### Coverage Upload Fails

- For public repos, Codecov token is optional
- For private repos, add `CODECOV_TOKEN` secret
- Check Codecov.io for repository access

### Linting Fails

Run locally to debug:
```bash
make lint
```

Fix issues and commit changes.

### Formatting Fails

Run locally to fix:
```bash
make format
git add .
git commit -m "Fix formatting"
```

### Tools Not Found

Ensure `tools.mod` dependencies are downloaded:
```bash
go mod download -modfile=tools.mod
```

## Workflow Execution Flow

### Pull Request Flow
```
PR Opened/Updated
       │
       ├─→ Quick Test (Linux)
       ├─→ Code Quality (Lint + Format)
       ├─→ macOS Integration
       └─→ Windows Integration
              │
              └─→ All Pass → Ready to Merge
```

### Release Flow
```
Tag Pushed (v*.*.*)
       │
       ├─→ Run Full Tests
       ├─→ Run Quality Checks
       │        │
       │        └─→ All Pass?
       │                │
       ├─→ Generate Changelog
       ├─→ Create Release
       └─→ Notify (Discord)
```

## Performance Metrics

**Average Execution Times** (with cache):

- Quick Test: 2 minutes
- Code Quality: 3 minutes
- macOS Integration: 5 minutes
- Windows Integration: 6 minutes
- **Complete PR**: 6 minutes (parallel)

## Contributing

When modifying workflows:

1. Test locally with `act` if possible
2. Use meaningful job and step names
3. Leverage Makefile commands for consistency
4. Add comments for complex steps
5. Set appropriate timeouts
6. Handle failures gracefully

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Go Actions Setup](https://github.com/actions/setup-go)
- [Codecov Action](https://github.com/codecov/codecov-action)
- [act - Local Testing](https://github.com/nektos/act)
