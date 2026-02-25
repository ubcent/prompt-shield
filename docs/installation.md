# Installation

## Homebrew (macOS)

### Official formula (long-term)

Once Velar is accepted into `homebrew/core`, install with:

```bash
brew install velar
```

### Project tap (available now)

```bash
brew tap dmitrybondarchuk/velar
brew install velar
```

## Post-install setup

A default config is created at `~/.velar/velar.yaml` during installation if missing.

Initialize local MITM certificates before intercepting HTTPS traffic:

```bash
velar ca init
```

Start the daemon service:

```bash
brew services start velar
```

Verify installation:

```bash
velar --version
velard --help
brew services list | rg velar
```

## Upgrade / uninstall

```bash
brew upgrade velar
brew services stop velar
brew uninstall velar
```
