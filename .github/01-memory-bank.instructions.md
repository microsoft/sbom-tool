---
applyTo: "**"
---

# Memory Bank Instructions for AI Chat Agents

## Why This Matters

AI agents are stateless by default—each new conversation starts from zero context. The Memory Bank solves this by creating persistent, structured context that survives across sessions. Without it, you waste time re-explaining project decisions, repeating discovered patterns, and rediscovering issues. Active context tracking prevents the agent from suggesting already-completed work or contradicting previous architectural decisions. The `learnings.md` file builds institutional knowledge about how your codebase works, turning every debugging session into reusable expertise. For teams, Memory Bank creates shared understanding—new contributors can read `activeContext.md` to understand current work instantly. Mandatory step completion tracking ensures progress isn't lost between sessions and provides audit trails for complex implementations. Think of Memory Bank as the agent's project journal: without it, every conversation is a blank slate; with it, the agent becomes a knowledgeable team member who remembers your project's unique context, patterns, and decisions.

## Memory Bank Locations

<notes>
Memory bank should be located in repo-root `.memory-bank/`
Reference this path to find the active context for any agent.
</notes>

## Required Files

<constraints>
**If any don't exist, you MUST create them before proceeding.**

- **`activeContext.md`**: Current work focus, recent changes, next steps, active decisions, and implementation details for the current feature. Keep this up to date while working. Mark todos with checkboxes using ☐ for incomplete and ✅ for complete. This file is cleared when work focus changes, so include as much detail as needed.
- **`learnings.md`**: Which components are used for what, how the code is structured, known issues and bugs. (Project technical assessment).
- **`userDirectives.md`** (optional): Permanent user specific instructions, tone preferences, stylistic rules, behavioral boundaries, and response priorities that MUST be respected in every interaction.
</constraints>

### `activeContext.md` Template

<format>
```markdown
# Active Context

## Current Work Focus
[Description of current task/feature]

## Recent Changes
- ✅ Completed items with checkmark
- ☐ Pending items with empty checkbox

## Active Decisions
[Key architectural or implementation decisions made]

## Next Steps
1. ☐ Step description
2. ☐ Step description
3. ✅ Completed step description

## Current State
[Summary of where we are in the implementation]
```
</format>

## Workflow

<instructions>
### 1. Starting New Chat Sessions

- At the beginning of each new chat session, read ALL Memory Bank files to initialize your understanding.
- Check for the existence of all required files under the package-local path.
- If ANY file is missing, STOP and create it. **Do not proceed without doing this.**
- Verify you have complete context before starting development.
- If the current work focus has changed, clear the `activeContext.md` file before continuing.

### 2. During Development

- Consistently follow the patterns, decisions, and context documented in the Memory Bank.
- **IMPORTANT:** When using tools (like writing files, executing commands), preface the action description with `MEMORY BANK ACTIVE: ` to signal you are operating based on the established context.
- **MANDATORY STEP COMPLETION TRACKING:**
  - **IMMEDIATELY** after completing ANY step from the "Next Steps" list in `activeContext.md`, you MUST update the file to mark that step as completed by changing `☐` to `✅`, as well as updating the current state.
  - This update must happen BEFORE proceeding to the next step.
  - Do not wait to batch multiple step completions—update after each individual step.
  - If a step has multiple sub-tasks, only mark it complete when ALL sub-tasks are finished.
- **CONTEXT UPDATE GUIDELINES:**
  - Read the current `activeContext.md` file before making any updates to avoid corruption.
  - Update in logical batches (complete related steps together) rather than individual steps when appropriate.
  - Verify markdown structure and formatting after each update.
  - If `activeContext.md` becomes malformed, STOP and completely rewrite it with current accurate state.
- **REGULAR CONTEXT UPDATES:** Update Memory Bank files (`activeContext.md` and `learnings.md`) after implementing significant changes, discovering new patterns, or encountering issues that should be documented for future reference.

### 3. Priority

- When context from Memory Bank files conflicts with general knowledge, **always prioritize the Memory Bank information** for this specific repository.
- Use the context provided to generate more relevant, accurate, and project-specific responses.
- Your ability to function effectively depends entirely on the accuracy and completeness of the Memory Bank. Maintain it diligently.
</instructions>

<system-reminder>
Memory Bank updates are MANDATORY after each completed step. Missing updates cause context rot and repeated work.
</system-reminder>

<system-reminder>
If Memory Bank conflicts with general knowledge, ALWAYS prefer Memory Bank content. It contains project-specific context.
</system-reminder>
