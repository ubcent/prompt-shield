# Task: VSCode Extension for Velar

## Objective
Create a VSCode extension that integrates Velar monitoring directly into the editor with inline warnings and status indicators.

## Current State
- Developers must check logs or web UI separately
- No IDE integration for immediate feedback
- No awareness of what data is being sent to AI tools from editor

## Specification

### Functional Requirements
1. Status bar indicator showing Velar connection status:
   - 🟢 Connected: Velar is running and proxying
   - 🟡 Degraded: Velar running but issues detected
   - 🔴 Disconnected: Velar not running
2. Real-time notifications when sensitive data is detected:
   - Toast notification: "Masked 2 emails in request to api.openai.com"
   - Inline decorations showing masked content in editor
3. Output panel showing recent Velar activity:
   - Last 20 requests with masked data summary
   - Clickable links to audit log entries
4. Commands:
   - `Velar: Start` - start Velar daemon
   - `Velar: Stop` - stop Velar daemon
   - `Velar: Open Dashboard` - open web UI in browser
   - `Velar: Show Audit Log` - open audit log in editor
5. Settings:
   - `velar.enabled` - enable/disable extension
   - `velar.autoStart` - auto-start Velar on VSCode launch
   - `velar.notifications` - show/hide toast notifications
   - `velar.port` - Velar proxy port (default 8080)

### Technical Requirements
1. TypeScript-based extension following VSCode API guidelines
2. Communicate with Velar via:
   - HTTP API (web UI endpoints)
   - Audit log file watching
   - Process management for daemon control
3. Extension structure:
   - `src/extension.ts` - main extension entry point
   - `src/statusBar.ts` - status bar indicator logic
   - `src/notifier.ts` - notification handling
   - `src/daemon.ts` - Velar daemon control
   - `src/auditLog.ts` - audit log parsing and watching
4. Bundle with webpack for minimal size
5. No external dependencies beyond VSCode API and Node.js stdlib

### Acceptance Criteria
- [ ] Extension installs from VSIX file
- [ ] Status bar shows correct Velar state
- [ ] Notifications appear when data is masked
- [ ] Commands start/stop Velar successfully
- [ ] Works on macOS, Linux, and Windows
- [ ] Extension size < 1MB
- [ ] No performance impact on VSCode startup
- [ ] Published to VSCode marketplace (future)

### Testing Requirements
1. Unit tests for daemon control logic
2. Integration tests with mock Velar instance
3. Test extension commands manually
4. Test on all three platforms (macOS, Linux, Windows)
5. Add tests in `vscode-extension/src/test/`

### Files to Create
- `vscode-extension/package.json` - extension manifest
- `vscode-extension/src/extension.ts` - main entry point
- `vscode-extension/src/statusBar.ts` - status bar logic
- `vscode-extension/src/notifier.ts` - notifications
- `vscode-extension/src/daemon.ts` - daemon control
- `vscode-extension/src/auditLog.ts` - log parsing
- `vscode-extension/src/test/suite/extension.test.ts` - tests
- `vscode-extension/tsconfig.json` - TypeScript config
- `vscode-extension/webpack.config.js` - bundling config
- `vscode-extension/README.md` - extension documentation
- `vscode-extension/.vscodeignore` - packaging exclusions

## UI Mockup

### Status Bar
```
[🟢 Velar: 3 masked]  ← clickable, opens output panel
```

### Notification
```
┌──────────────────────────────────────────┐
│ Velar masked 2 emails in OpenAI request  │
│ [View Details]  [Dismiss]                │
└──────────────────────────────────────────┘
```

### Output Panel
```
VELAR ACTIVITY
──────────────────────────────────────────
14:32:15 api.openai.com
         Masked: 2 × EMAIL
         Latency: 45ms
         [View in Dashboard]

14:31:58 chatgpt.com
         Masked: 1 × PHONE
         Latency: 38ms
         [View in Dashboard]
```

## Implementation Notes

### Daemon Control
```typescript
import { spawn } from 'child_process';

class VelarDaemon {
  async start(): Promise<void> {
    const velarPath = findVelarBinary();
    spawn(velarPath, ['start'], { detached: true });
  }

  async stop(): Promise<void> {
    const velarPath = findVelarBinary();
    spawn(velarPath, ['stop']);
  }

  async isRunning(): Promise<boolean> {
    try {
      const response = await fetch('http://localhost:8081/api/health');
      return response.ok;
    } catch {
      return false;
    }
  }
}
```

### Audit Log Watching
```typescript
import { watch } from 'fs';

function watchAuditLog(onNewEntry: (entry: AuditEntry) => void) {
  const logPath = expandPath('~/.velar/audit.log');
  watch(logPath, () => {
    // Read new lines and parse JSONL
    const entries = parseNewLogEntries(logPath);
    entries.forEach(onNewEntry);
  });
}
```

## Non-Goals
- Inline code modification or suggestions
- AI code completion integration
- Multi-workspace support (single workspace only for now)
- Custom themes or extensive UI customization
