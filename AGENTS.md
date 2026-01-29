# SBOM Tool Agent Instructions

This repository contains the Microsoft SBOM Tool, a .NET 8 solution for generating
SPDX 2.2 and SPDX 3.0 compatible Software Bill of Materials (SBOM) files.

## Repository Structure

- `src/Microsoft.Sbom.Api/` - Core API for SBOM generation and validation
- `src/Microsoft.Sbom.Common/` - Shared utilities and abstractions
- `src/Microsoft.Sbom.Contracts/` - Public contracts and interfaces
- `src/Microsoft.Sbom.Parsers.Spdx22SbomParser/` - SPDX 2.2 format parser
- `src/Microsoft.Sbom.Parsers.Spdx30SbomParser/` - SPDX 3.0 format parser
- `src/Microsoft.Sbom.Tool/` - Standalone CLI executable
- `src/Microsoft.Sbom.DotNetTool/` - .NET global tool packaging
- `src/Microsoft.Sbom.Adapters/` - External format adapters
- `src/Microsoft.Sbom.Extensions/` - Extension points
- `src/Microsoft.Sbom.Extensions.DependencyInjection/` - DI integration
- `src/Microsoft.Sbom.Targets/` - MSBuild targets for SBOM generation
- `test/` - All test projects

## Build and Test Commands

- Build solution: `dotnet build Microsoft.Sbom.sln`
- Run all tests: `dotnet test Microsoft.Sbom.sln`
- Run specific tests: `dotnet test test/Microsoft.Sbom.Api.Tests/`

## Technology Constraints

- Target: .NET 8 (`net8.0`)
- Logging: Serilog
- CLI: Spectre.Console.Cli
- Mapping: AutoMapper
- Component Detection: Microsoft.ComponentDetection libraries
- Serialization: `System.Text.Json` preferred; `Newtonsoft.Json` for legacy compatibility

## Development Guidelines

- Prefer small, focused changes aligned with existing patterns
- Keep public APIs stable; prefer extending over breaking signatures
- Use `async`/`await` and `Task`-based methods for I/O
- Use guards (`ArgumentNullException.ThrowIfNull`) for public method arguments
- Fail fast for invalid inputs; validate early before expensive work
- Prefer `var` when type is obvious, otherwise explicit types
- Use `readonly` fields where practical

## Filesystem and IO

- Use abstractions over static `System.IO` methods where possible
- Avoid hardcoding absolute paths; use relative paths and `Path` helpers
- Code for cross-platform compatibility; avoid Windows-specific paths

## Error Handling

- Use clear, actionable error messages
- Surface validation issues as structured results, not only exceptions
- Do not log secrets, sensitive paths, or internal-only identifiers

## Testing

- All test projects use MSTest
- Run tests frequently during development
- Write tests for new functionality and bug fixes
- Test behavior, not implementation details

## PR Guidelines

- Propose minimal diffs that satisfy the request
- Suggest corresponding test updates for any behavior change
- Keep changes easy to rebase: small commits, clear intent
- Avoid generating large, intrusive refactors unless explicitly requested

## Memory Bank

> **Detailed memory file templates:** See [`.memory-bank/AGENTS.md`](.memory-bank/AGENTS.md)

### Why This Matters

AI agents are stateless—each conversation starts from zero context. The Memory Bank
creates persistent, structured context that survives across sessions. Without it,
you waste time re-explaining decisions, repeating patterns, and rediscovering issues.
Think of Memory Bank as the agent's project journal: with it, the agent becomes a
knowledgeable team member who remembers your project's unique context and decisions.

### Files

At the start of each session, read all files in `.memory-bank/`:

| File | Purpose | Update Frequency |
|------|---------|------------------|
| `activeContext.md` | Current task, recent changes, next steps | After each step |
| `learnings.md` | Technical patterns, known issues, code structure | When patterns discovered |
| `userDirectives.md` | User preferences, style rules, boundaries | Rarely (user-driven) |

### Workflow

#### 1. Starting New Chat Sessions

<constraints>
**MANDATORY**: Before answering ANY user request or performing ANY work:

1. Check if `.memory-bank/` directory exists with ALL three required files:
   - `activeContext.md`
   - `learnings.md`
   - `userDirectives.md`
2. If ANY file is missing, **STOP and create it** using templates in [`.memory-bank/AGENTS.md`](.memory-bank/AGENTS.md)
3. Do NOT proceed with the user's request until Memory Bank is initialized
</constraints>

- Read ALL Memory Bank files to initialize your understanding
- If required files are missing, **STOP and create them** using templates in [`.memory-bank/AGENTS.md`](.memory-bank/AGENTS.md)
- If the current work focus has changed, clear `activeContext.md` before continuing
- Confirm Memory Bank is loaded: "📚 Memory Bank loaded — current focus: [topic]"

#### 2. During Development

- Follow patterns, decisions, and context documented in the Memory Bank
- **IMPORTANT:** When using tools (writing files, executing commands), preface the action
  description with `MEMORY BANK ACTIVE: ` to signal you are operating based on established context

**Mandatory Step Completion Tracking:**

- **IMMEDIATELY** after completing ANY step from "Next Steps" in `activeContext.md`,
  update the file to mark that step as completed (change ☐ to ✅)
- This update must happen **BEFORE** proceeding to the next step
- **Do NOT batch multiple step completions**—update after each individual step
- Also update the "Current State" section to reflect progress

**Context Update Guidelines:**

- Read the current `activeContext.md` before making updates to avoid corruption
- **If `activeContext.md` becomes malformed, STOP and completely rewrite it** with current accurate state
- Update `learnings.md` when discovering new patterns, issues, or technical decisions

#### 3. Priority Rules

- When Memory Bank conflicts with general knowledge, **always prioritize Memory Bank**
- Your ability to function effectively depends on the accuracy of the Memory Bank—maintain it diligently

---

> **⚠️ REMINDER:** Memory Bank updates are MANDATORY after each completed step.
> Missing updates cause context rot and repeated work.

> **⚠️ REMINDER:** If Memory Bank conflicts with general knowledge,
> ALWAYS prefer Memory Bank content. It contains project-specific context.
