# GitHub Actions Workflows

This directory contains CI/CD workflows for the caddy-certstore project.

## Important Note

**Default Runner: macOS**

The `tailscale/certstore` library does not support Linux. All workflows use **macOS** as the default runner for unit tests, linting, and quality checks.

**Supported Platforms:**
- ✅ macOS (Darwin) - Full support
- ✅ Windows - Full support
- ❌ Linux - Not supported by certstore library

## Workflows

### 🧪 test.yml - Comprehensive Testing
**Triggers:** Push to main/master/develop, Pull Requests, Manual

Tests the module across supported platforms using Go version from `.go-version`:

- **macOS (Unit)**: Unit tests only (SKIP_KEYCHAIN_TESTS=1)
- **macOS (Integration)**: Full integration tests with Keychain
- **Windows (Integration)**: Full integration tests with Certificate Store

**Coverage**: Results uploaded to Codecov with platform-specific flags.

**Note**: No Linux runner since certstore library doesn't support Linux.

### 🔍 pr.yml - Pull Request Checks
**Triggers:** Pull Request events (opened, synchronize, reopened)

Fast validation for pull requests with 4 jobs:

- **Quick Test**: Unit tests on macOS (fastest feedback)
- **Code Quality**: Runs `make lint` and `make format` checks on macOS
- **macOS Integration**: Full integration tests
- **Windows Integration**: Full integration tests

**All checks use macOS or Windows** - no Linux runners.

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

Comprehensive code quality checks (all on **macOS**):

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

### 🍎 macOS as Default Runner

Since `tailscale/certstore` doesn't support Linux, all default operations run on macOS:

```yaml
jobs:
  quick-test:
    runs-on: macos-latest  # Not ubuntu-latest
```

**Cost Consideration**: macOS runners have a 10x multiplier on GitHub Actions minutes compared to Linux. However, this is necessary for the project to function.

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

1. ✅ **Quick Test** (macOS) - Unit tests (~3 min)
2. ✅ **Code Quality** (macOS) - Linting + Formatting checks (~4 min)
3. ✅ **macOS Integration** - Full integration tests (~6 min)
4. ✅ **Windows Integration** - Full integration tests (~7 min)

**Total PR validation time: ~7 minutes** (parallel execution)

### 📊 Platform Support

| Platform | Runner | Test Type | Store Type | Duration |
|----------|--------|-----------|------------|----------|
| macOS    | macos-latest | Unit | N/A | ~3 min |
| macOS    | macos-latest | Integration | Keychain | ~6 min |
| Windows  | windows-latest | Integration | CertStore | ~7 min |
| Linux    | ❌ Not supported | - | - | - |

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

Both are set on unit test jobs to test the code without certificate store access.

## Local Testing

Test workflows locally using [act](https://github.com/nektos/act):

```bash
# Install act
brew install act  # macOS

# Note: act uses Linux containers by default, which won't work
# You need to use --platform flag or test manually
```

**Better approach**: Test manually with the same commands:

```bash
# What CI runs for unit tests
SKIP_KEYCHAIN_TESTS=1 SKIP_CERTSTORE_TESTS=1 go test -v -race ./...

# What CI runs for quality
make lint
make format

# What CI runs for integration
go test -v -race ./...
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
echo "1.25.4" > .go-version
git add .go-version
git commit -m "Update Go to 1.25.4"
```

All workflows will automatically use this version.

### Adjusting Coverage Threshold

Edit `quality.yml`:
```bash
if (( $(echo "$COVERAGE < 30.0" | bc -l) )); then
```

### Modifying Linter Settings

Edit `.golangci.yml` in the repository root, or update the `make lint` target in `Makefile`.

## Cost Considerations

### GitHub Actions Minutes

**macOS runners cost 10x Linux runners**:
- Linux: 1 minute = 1 minute
- macOS: 1 minute = 10 minutes (10x multiplier)
- Windows: 1 minute = 2 minutes (2x multiplier)

**Typical PR cost**:
- Quick Test (macOS): 3 min × 10 = 30 billable minutes
- Quality (macOS): 4 min × 10 = 40 billable minutes
- macOS Integration: 6 min × 10 = 60 billable minutes
- Windows Integration: 7 min × 2 = 14 billable minutes
- **Total**: ~144 billable minutes per PR

**Why macOS?**: Required because certstore library doesn't support Linux. No alternative.

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

### "certstore not supported on linux" Error

This is expected! The certstore library doesn't support Linux. Make sure you're using macOS or Windows runners.

## Workflow Execution Flow

### Pull Request Flow
```
PR Opened/Updated
       │
       ├─→ Quick Test (macOS)
       ├─→ Code Quality (macOS)
       ├─→ macOS Integration
       └─→ Windows Integration
              │
              └─→ All Pass → Ready to Merge
```

### Release Flow
```
Tag Pushed (v*.*.*)
       │
       ├─→ Run Full Tests (macOS + Windows)
       ├─→ Run Quality Checks (macOS)
       │        │
       │        └─→ All Pass?
       │                │
       ├─→ Generate Changelog
       ├─→ Create Release
       └─→ Notify (Discord)
```

## Performance Metrics

**Average Execution Times** (with cache):

- Quick Test (macOS): 3 minutes
- Code Quality (macOS): 4 minutes
- macOS Integration: 6 minutes
- Windows Integration: 7 minutes
- **Complete PR**: 7 minutes (parallel)

**Billable Minutes** (with GitHub Actions multipliers):
- Quick Test: 30 minutes (3 × 10)
- Quality: 40 minutes (4 × 10)
- macOS Integration: 60 minutes (6 × 10)
- Windows Integration: 14 minutes (7 × 2)
- **Total per PR**: ~144 billable minutes

## Contributing

When modifying workflows:

1. Remember that Linux is not supported
2. Use macOS for all default operations
3. Test manually with the same commands CI uses
4. Use meaningful job and step names
5. Leverage Makefile commands for consistency
6. Add comments for complex steps
7. Set appropriate timeouts
8. Handle failures gracefully

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Go Actions Setup](https://github.com/actions/setup-go)
- [Codecov Action](https://github.com/codecov/codecov-action)
- [GitHub Actions Pricing](https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions)
