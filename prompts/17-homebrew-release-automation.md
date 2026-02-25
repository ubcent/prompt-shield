# Task: Homebrew Release Automation

## Objective
Automatically publish Velar binaries to Homebrew when a new release is created on GitHub, enabling macOS users to install with `brew install velar`.

## Current State
- No Homebrew formula for Velar
- Release process is manual
- Users must download binaries manually from GitHub
- No easy installation path for macOS users

## Specification

### Functional Requirements
1. Homebrew formula that installs Velar binaries:
   - Downloads correct binary for user's architecture (arm64/x86_64)
   - Places binaries in correct locations (`velar`, `velard`)
   - Creates configuration directory (`~/.velar`)
   - Generates initial config file if missing
2. Automatic formula updates on GitHub release:
   - GitHub Action triggered on release creation
   - Updates formula with new version and checksums
   - Creates PR in Homebrew tap repository
   - Auto-merges on CI success (or manual review)
3. Support for both:
   - Official Homebrew repository (long-term)
   - Community tap (`homebrew-velar`) in project repo (immediate)
4. Version management:
   - Semantic versioning alignment
   - Dependency declarations (Go runtime if needed)
   - Deprecation path for old formulas

### Technical Requirements
1. Create Homebrew formula at:
   - `Formula/velar.rb` (for main Homebrew repo eventually)
   - `homebrew-velar/Formula/velar.rb` (temporary tap)
2. Formula structure:
   ```ruby
   class Velar < Formula
     desc "Security proxy for AI provider communication"
     homepage "https://github.com/dmitrybondarchuk/prompt-shield"
     
     # URLs and checksums updated by automation
     on_macos do
       on_arm64 do
         url "https://github.com/.../velar-darwin-arm64-vX.Y.Z.tar.gz"
         sha256 "abc123..."
       end
       on_intel do
         url "https://github.com/.../velar-darwin-x86_64-vX.Y.Z.tar.gz"
         sha256 "def456..."
       end
     end
     
     def install
       bin.install "psd", "psctl", "velar", "velard"
       # Create config directory
       config_dir = File.expand_path("~/.velar")
       mkdir_p config_dir
       # Install example config if missing
       etc_path = etc/"velar"
       mkdir_p etc_path
     end
     
     service do
       run [opt_bin/"velard", "-config", "#{ENV['HOME']}/.velar/velar.yaml"]
       keep_alive true
     end
   end
   ```
3. GitHub Action workflow:
   - Triggered on GitHub release (tag push)
   - Extracts version from tag
   - Downloads release artifacts
   - Computes SHA256 checksums
   - Updates formula file
   - Pushes to Homebrew tap with PR
4. Release workflow must produce:
   - `velar-darwin-arm64-vX.Y.Z.tar.gz` (with checksum)
   - `velar-darwin-x86_64-vX.Y.Z.tar.gz` (with checksum)
   - Both contain: `velar`, `velard` binaries
5. Tap repository setup:
   - Create `homebrew-velar` repository at GitHub
   - Configure branch protection and automation
   - Auto-publish releases from main branch

### Acceptance Criteria
- [ ] Homebrew formula installs Velar successfully on macOS
- [ ] Binary is executable and runs without errors
- [ ] Configuration directory created correctly
- [ ] Service definition works with `brew services start velar`
- [ ] Updates work: `brew upgrade velar`
- [ ] Both arm64 and x86_64 architectures supported
- [ ] GitHub Action updates formula on release
- [ ] Formula PR auto-merges successfully
- [ ] Installation works offline after formula cached
- [ ] Uninstall removes binaries and service
- [ ] All existing tests pass

### Testing Requirements
1. Manual test of formula locally:
   - `brew install --build-from-source ./Formula/velar.rb`
   - Test all installed binaries
   - Test service management
   - Test uninstall cleanup
2. Test formula with multiple releases:
   - Create test releases
   - Verify formula updates correctly
   - Test upgrade from old version
3. Test Darwin (macOS) compatibility:
   - Run on Intel Mac
   - Run on Apple Silicon Mac
   - Test code signing (if applicable)
4. Test GitHub Action:
   - Trigger on test release
   - Verify formula update PR created
   - Check checksums accuracy
5. Add tests in workflow: `.github/workflows/release-homebrew.yml`

### Files to Create/Modify
- `homebrew-velar/Formula/velar.rb` - NEW: Homebrew formula
- `.github/workflows/release.yml` - MODIFY: Add binary build for Darwin
- `.github/workflows/homebrew-release.yml` - NEW: Automation for Homebrew updates
- `.github/workflows/homebrew-test.yml` - NEW: Test formula on each commit
- `scripts/build-darwin.sh` - NEW: Build macOS binaries (arm64/x86_64)
- `scripts/checksum.sh` - NEW: Generate SHA256 checksums
- `docs/installation.md` - MODIFY: Add Homebrew installation instructions
- `README.md` - MODIFY: Add Homebrew badge and installation section

## Implementation Details

### Build Process
```bash
# For each release, build and package:
./scripts/build-darwin.sh arm64 v1.0.0    # → velar-darwin-arm64-v1.0.0.tar.gz
./scripts/build-darwin.sh x86_64 v1.0.0   # → velar-darwin-x86_64-v1.0.0.tar.gz

# Generate checksums:
./scripts/checksum.sh v1.0.0
# → Produces checksums for formula update
```

### Formula Update Automation
```yaml
# .github/workflows/homebrew-release.yml
name: Homebrew Release

on:
  release:
    types: [published]

jobs:
  update-formula:
    runs-on: ubuntu-latest
    steps:
      - name: Extract version
        run: echo "VERSION=${GITHUB_REF#refs/tags/}" >> $GITHUB_ENV
      
      - name: Download release artifacts
        uses: actions/download-artifact@v3
        with:
          name: darwin-binaries
      
      - name: Compute checksums
        run: |
          SHA256_ARM64=$(sha256sum velar-darwin-arm64-${VERSION}.tar.gz | cut -d' ' -f1)
          SHA256_X86=$(sha256sum velar-darwin-x86_64-${VERSION}.tar.gz | cut -d' ' -f1)
          echo "SHA256_ARM64=$SHA256_ARM64" >> $GITHUB_ENV
          echo "SHA256_X86=$SHA256_X86" >> $GITHUB_ENV
      
      - name: Update formula
        run: |
          python3 scripts/update-homebrew-formula.py \
            --version $VERSION \
            --sha256-arm64 $SHA256_ARM64 \
            --sha256-x86 $SHA256_X86
      
      - name: Create PR
        uses: peter-evans/create-pull-request@v4
        with:
          token: ${{ secrets.HOMEBREW_TAP_TOKEN }}
          repo: dmitrybondarchuk/homebrew-velar
          branch: update-velar-${{ env.VERSION }}
          title: "chore: update Velar to ${{ env.VERSION }}"
          body: "Automated update from release ${{ env.VERSION }}"
          auto-merge: true
```

### Service Management
```ruby
# In formula - enables `brew services start velar`
service do
  run [opt_bin/"velard", "-config", "#{ENV['HOME']}/.velar/velar.yaml"]
  keep_alive true
  require_root false  # Can run as user
  working_dir ENV['HOME']
end
```

### Configuration Setup
```ruby
# Create default config on first install
def post_install
  config_dir = File.expand_path("~/.velar")
  mkdir_p config_dir
  
  config_file = "#{config_dir}/velar.yaml"
  unless File.exist?(config_file)
    File.write(config_file, default_config)
  end
end

private

def default_config
  <<~EOS
    # Velar Configuration
    port: 9292
    cert_file: "#{config_dir}/.velar-ca-cert.pem"
    key_file: "#{config_dir}/.velar-ca-key.pem"
    log_file: "#{config_dir}/audit.log"
  EOS
end
```

## Installation Examples

### After Implementation
```bash
# Install from Homebrew
brew install velar

# Or from tap (during development)
brew tap dmitrybondarchuk/velar
brew install velar

# Start as service
brew services start velar

# Check status
brew services list
# velar started dmitrybondarchuk ...

# View logs
log stream --predicate 'process == "velard"'

# Upgrade to latest
brew upgrade velar

# Uninstall
brew uninstall velar
```

## Success Metrics
- Users can install Velar with single `brew install velar` command
- Installation takes < 30 seconds on typical connection
- Formula keeps up-to-date automatically with releases
- Support for both Intel and Apple Silicon Macs
- Zero manual steps for formula maintenance


