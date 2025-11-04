# CI/CD Pipeline

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Code Changes                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
            ┌─────────────────────────────────┐
            │     Trigger Event Detected      │
            └─────────────────────────────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
    ┌──────────┐      ┌──────────┐      ┌──────────┐
    │   Push   │      │    PR    │      │   Tag    │
    └──────────┘      └──────────┘      └──────────┘
           │                  │                  │
           ▼                  ▼                  ▼
    ┌──────────┐      ┌──────────┐      ┌──────────┐
    │  Tests   │      │ PR Check │      │ Release  │
    │ Quality  │      └──────────┘      └──────────┘
    └──────────┘
```

## Workflow Execution Matrix

### test.yml - Full Test Suite

| Platform | Go Versions | Test Type | Store Type | Privileges |
|----------|-------------|-----------|------------|------------|
| Linux    | 1.21-1.23   | Unit      | N/A        | None       |
| macOS    | 1.21-1.23   | Integration | Keychain | None (user) |
| Windows  | 1.21-1.23   | Integration | CertStore | None (user) |

**Total Jobs**: 9 test jobs + 2 quality jobs = **11 concurrent jobs**

### pr.yml - Pull Request Validation

| Job | Platform | Duration | Purpose |
|-----|----------|----------|---------|
| Quick Test | Linux | ~2 min | Fast feedback |
| macOS Integration | macOS | ~5 min | Keychain validation |
| Windows Integration | Windows | ~5 min | CertStore validation |

**Total Jobs**: 3 jobs (fail-fast: false)

### quality.yml - Code Quality

| Check | Tool | Frequency |
|-------|------|-----------|
| Linting | golangci-lint | Push/PR |
| Security | Gosec + govulncheck | Push/PR/Weekly |
| Dependencies | go mod verify | Push/PR |
| Formatting | gofmt + goimports | Push/PR |
| Coverage | go test -cover | Push/PR |

**Total Jobs**: 5 quality checks

### release.yml - Release Process

```
Tag Pushed (v*.*.*)
       │
       ├─→ Run Full Test Suite (test.yml)
       │        │
       │        ├─→ All Tests Pass?
       │        │        │
       │        │        ├─→ Yes: Continue
       │        │        └─→ No: Fail Release
       │        │
       ├─→ Generate Changelog
       │
       ├─→ Create GitHub Release
       │        │
       │        ├─→ Release Notes
       │        ├─→ Installation Instructions
       │        └─→ Asset Links
       │
       └─→ Send Notifications (optional)
                │
                └─→ Discord Webhook
```

## Platform-Specific Behaviors

### Linux Runner (ubuntu-latest)
```yaml
Environment:
  - SKIP_KEYCHAIN_TESTS: 1
  - SKIP_CERTSTORE_TESTS: 1

Actions:
  ✓ Download dependencies
  ✓ Run unit tests with race detector
  ✓ Generate coverage report
  ✗ Skip integration tests (no certificate store)

Duration: ~2-3 minutes
```

### macOS Runner (macos-latest)
```yaml
Environment:
  - No skip flags (run all tests)

Actions:
  ✓ Download dependencies
  ✓ Verify test certificates exist
  ✓ Run unit tests
  ✓ Run keychain integration tests
  ✓ Import certificates to login keychain
  ✓ Test certificate loading
  ✓ Cleanup keychain
  ✓ Generate coverage report

Duration: ~5-7 minutes
```

### Windows Runner (windows-latest)
```yaml
Environment:
  - No skip flags (run all tests)

Actions:
  ✓ Download dependencies (PowerShell)
  ✓ Verify test certificates exist
  ✓ Run unit tests
  ✓ Run certificate store integration tests
  ✓ Import PFX to CurrentUser\My
  ✓ Test certificate loading
  ✓ Cleanup certificate store
  ✓ Generate coverage report

Duration: ~5-8 minutes
```

## Caching Strategy

All workflows use GitHub Actions caching for faster builds:

```yaml
# Linux
~/.cache/go-build
~/go/pkg/mod

# macOS
~/Library/Caches/go-build
~/go/pkg/mod

# Windows
~\AppData\Local\go-build
~\go\pkg\mod
```

**Cache Key**: `${{ runner.os }}-go-${{ go-version }}-${{ hashFiles('**/go.sum') }}`

This reduces build time from ~5 minutes to ~2 minutes on cache hit.

## Coverage Reporting

Coverage is collected from all platforms and uploaded to Codecov:

```
┌──────────────────────────────────────────┐
│         Coverage Collection              │
├──────────────────────────────────────────┤
│  Linux:   Unit Tests (30%)               │
│  macOS:   Unit + Integration (45%)       │
│  Windows: Unit + Integration (45%)       │
└──────────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │   Codecov Service    │
         └──────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Coverage Report     │
         │  • By Platform       │
         │  • By Package        │
         │  • Trend Over Time   │
         └──────────────────────┘
```

## Notification Flow

```
Release Created
      │
      ├─→ GitHub Release Page
      │        └─→ Markdown notes
      │        └─→ Changelog
      │        └─→ Installation instructions
      │
      └─→ Optional: Discord Webhook
               └─→ Channel notification
               └─→ Release link
```

## Workflow Triggers Summary

| Workflow | Push | PR | Tag | Schedule | Manual |
|----------|------|----|----|----------|--------|
| test.yml | ✓    | ✓  | -  | -        | ✓      |
| pr.yml   | -    | ✓  | -  | -        | -      |
| quality.yml | ✓ | ✓  | -  | Weekly   | -      |
| release.yml | - | -  | ✓  | -        | ✓      |

## Performance Metrics

**Average Execution Times** (with cache):

- Quick Test (Linux): 2 minutes
- Full Test (Linux): 3 minutes
- Full Test (macOS): 5 minutes
- Full Test (Windows): 6 minutes
- Quality Checks: 4 minutes
- Complete PR Validation: 8 minutes (parallel)
- Full Test Suite: 10 minutes (parallel)

**Cost Estimation** (GitHub Actions Free Tier):

- Linux: Free (unlimited for public repos)
- macOS: 10x multiplier
- Windows: 2x multiplier

For a typical PR with all checks: ~50 minutes of billable time

## Best Practices

1. **Use Matrix Builds**: Test across multiple Go versions simultaneously
2. **Cache Dependencies**: Speeds up builds significantly
3. **Fail Fast for PRs**: Get quick feedback on obvious issues
4. **Platform-Specific Tests**: Only run integration tests where supported
5. **Security Scanning**: Weekly scheduled runs catch new vulnerabilities
6. **Coverage Threshold**: Prevent coverage regression (30% minimum)
7. **Clean Up Resources**: Always defer cleanup in integration tests

## Monitoring

Track workflow health in GitHub repository insights:

- Actions → Workflow runs
- Settings → Actions → Usage this month
- Pull requests → Checks tab

Set up notifications:

- Watch repository → Custom → Actions
- Slack/Discord integration via webhooks
