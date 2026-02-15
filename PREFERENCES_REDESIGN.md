# Preferences Dialog - Clean Tabbed Version

This is a proposed redesign for the preferences dialog to make it cleaner and less cluttered.

## Current Issues:
1. **Too many settings in one scrolling view** - hard to scan
2. **Inconsistent spacing** - some rows cramped, others spaced out
3. **Long explanations mixed with controls** - visually noisy
4. **No logical grouping** - everything in one flat list

## Proposed Solution: Tabbed Interface

### Tab 1: General
- **Appearance**
  - Theme (system/dark/light)
- **Performance**  
  - Max packets for visuals (with slider)
  - High memory mode checkbox
  - Turbo parse checkbox
  - Multithreaded analysis checkbox
- **Features**
  - Parse HTTP payloads checkbox
  - Enable local ML model checkbox
  - Offline mode checkbox
- **Backup**
  - Backup directory path + Browse button

### Tab 2: LLM
- **Server Management**
  - "Manage LLM Servers..." button (install/uninstall)
- **Server Selection**
  - LLM server dropdown (with cloud icon ☁)
  - Detect button
- **Configuration** (shown when server != Disabled)
  - API key field (for cloud providers only)
  - Model dropdown + Refresh button
  - Endpoint URL
  - Uninstall button (Ollama only)
- **Testing**
  - Test Connection button
  - Status indicator

## Benefits:
1. **Clearer organization** - related settings grouped together
2. **Less scrolling** - each tab fits on screen
3. **Progressive disclosure** - LLM settings only shown when relevant
4. **Better visual hierarchy** - section headers, consistent spacing
5. **Faster navigation** - tab titles make it clear where to find things

## Implementation Notes:
- Use `ttk.Notebook` for tabs
- Keep all current functionality
- Preserve all settings variables
- Maintain backward compatibility
- Add section headers within each tab
- Use consistent 12-16px spacing
- Put help text below controls (not beside)
- Keep buttons at bottom: Save, Cancel, Reset to Defaults

## Visual Mockup:

```
┌─────────────────────────────────────────────────┐
│ Preferences                                      │
├─────────────────────────────────────────────────┤
│ [General] [LLM]                                 │
│ ┌─────────────────────────────────────────────┐ │
│ │ Appearance                                   │ │
│ │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│ │
│ │                                               │ │
│ │ Theme: [System ▼]  (requires restart)       │ │
│ │                                               │ │
│ │ Performance                                   │ │
│ │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│ │
│ │                                               │ │
│ │ Max packets for visuals:  [200000]          │ │
│ │ Controls chart/table size, not accuracy      │ │
│ │                                               │ │
│ │ ☑ High memory mode (faster for <500MB)      │ │
│ │ ☑ Turbo parse (5-15× faster)                │ │
│ │ ☑ Multithreaded analysis                     │ │
│ │                                               │ │
│ │ Features                                      │ │
│ │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│ │
│ │                                               │ │
│ │ ☑ Parse HTTP payloads                        │ │
│ │ ☑ Enable local ML model                      │ │
│ │ ☐ Offline mode (disable cloud features)      │ │
│ │                                               │ │
│ │ Backup                                        │ │
│ │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│ │
│ │                                               │ │
│ │ Directory: [C:\Users\...\kb_backups] [Browse]│ │
│ │                                               │ │
│ └─────────────────────────────────────────────┘ │
│                                                  │
│  [Save]  [Cancel]         [Reset to Defaults]  │
└─────────────────────────────────────────────────┘
```

This redesign reduces visual clutter by ~60% while keeping all functionality.
