# Memory Bank Templates

This directory contains persistent context for AI agents across chat sessions.
For operational workflow, see [root AGENTS.md](../AGENTS.md#memory-bank).

Files in this folder (except this AGENTS.md) are git-ignored — each developer
maintains their own local context.

## Required Files

**If any file is missing, create it using the templates below.**

| File | Purpose | Update Frequency |
|------|---------|------------------|
| `activeContext.md` | Current task, recent changes, next steps, active decisions | After each step |
| `learnings.md` | Technical patterns, known issues, code structure | When patterns discovered |
| `userDirectives.md` | User preferences, style rules, boundaries | Rarely (user-driven) |

## File Templates

If any file is missing, create it using the templates below.

### `activeContext.md`

```markdown
# Active Context

## Current Work Focus
[Description of current task/feature being worked on]

## Recent Changes
- ✅ Completed items with checkmark
- ☐ Pending items with empty checkbox

## Active Decisions
[Key architectural or implementation decisions made during this work]

## Next Steps
1. ☐ Step description
2. ☐ Step description

## Current State
[Summary of where we are in the implementation]
```

### `learnings.md`

```markdown
# Project Learnings

## Code Structure

### NormalizedEntities
- `NormalizedBuildDocument` is the root document model
- Format-agnostic; SPDX-specific logic stays in adapters
- When adding fields, must update both SPDX 2.x and 3.x adapters

### Adapters
- SPDX 2.2: stable, avoid breaking changes
- SPDX 3.0: under active development, JSON-LD format

### CLI
- Thin layer over Core workflows
- No business logic here; delegate to workflows

## Known Issues
- [Document any known bugs, quirks, or workarounds]

## Patterns Discovered
- [Document patterns learned during development]

## Technical Decisions
- [Document significant architectural decisions and rationale]
```

### `userDirectives.md`

```markdown
# User Directives

## Response Style
- [Preferred tone, verbosity, format preferences]

## Behavioral Boundaries
- [Things the agent should never do]

## Priorities
- [What matters most: speed vs quality, minimal vs comprehensive, etc.]

## Project-Specific Rules
- [Any additional rules specific to how you want to work]
```

## Workflow

See [root AGENTS.md](../AGENTS.md#memory-bank) for operational workflow instructions.
