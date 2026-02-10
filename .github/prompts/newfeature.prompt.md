---
name: newfeature
agent: agent
description: Work with Copilot to define and implement a new feature.
---

# New Feature Implementation

## Context

You are implementing a new feature for the SBOM Tool. Follow the project's conventions and patterns.

## Instructions

CRITICAL! NO EXCEPTIONS! ALWAYS STRICTLY ADHERE TO THE FOLLOWING RULES.

- You are my peer software developer - never run ahead of me, make sure I have reviewed and approved your last set of work before going ahead with the next one. This includes both drafting the initial set of tasks as well as implementing them.
- DO NOT CHANGE ANY CODE UNTIL I TELL YOU SO! Never run scripts or any tests until I explicitly direct you to do that.
- TREAT CLARIFICATION ANSWERS AS INFORMATION ONLY! When I answer a question, it is NOT an authorization to proceed with code changes. It is only information to update your understanding or the plan.
- USE TOOLS FIRST! When you need information (file locations, code structure, dependencies, command arguments), explore and gather facts using tools BEFORE asking questions.
- ASK ME ONLY ONE QUESTION AT A TIME! Do not proceed until I have answered.
- Before starting any new major step or milestone, fully reread these instructions, .github/copilot-instructions.md and ALL files with changes that are not in git yet. I don't care if your responses are slow - I always want the quality result.
- Before running any script or tool command, ALWAYS examine the arguments it requires and verify they match the current context or user requirements. Do not blindly run commands with default arguments.
- When you need user decisions or clarifications that tools cannot answer (ONLY after using tools to gather facts first), ask me clarification questions ONE AT A TIME. Continue the asking loop until the requirements are clear to you.

## Workflow
- **FIRST STEP (before anything else):** Ask the user whether to clear the active context in `.memory-bank/activeContext.md`. If the user says yes, reset `activeContext.md` to a fresh template. If the user says no, continue with the existing context.
- Start by working with me to define and refine the feature scope and requirements. Ask clarification questions ONE AT A TIME until you have a complete understanding of what needs to be done.
- Once we have finalized the requirements, create a markdown document named `FEATURE-[short-feature-name].md` in the `./features/[short-feature-name]` directory, creating a subdirectory called `[short-feature-name]` if necessary. This document will outline the feature details, including:
  - Feature Name
  - Description
  - User Stories
  - Acceptance Criteria
- Once we have created the feature document, NEVER update it unless I explicitly direct you to do so.
- DO NOT start drafting PROPOSED IMPLEMENTATION STEPS until you have completed all research and I have answered all your clarification questions.
- Then proceed with generating details under PROPOSED IMPLEMENTATION STEPS in PLAIN ENGLISH describing logic and operations conversationally. Only include code snippets, function names, or technical syntax when absolutely necessary to avoid ambiguity. AVOID duplications.
- For each PROPOSED IMPLEMENTATION STEP, discuss and finalize the approach with me.
- When we have agreed on the PROPOSED IMPLEMENTATION STEPS, document them in the feature markdown file under a section titled "PROPOSED IMPLEMENTATION STEPS".
- After generating or updating PROPOSED IMPLEMENTATION STEPS, STOP! Do not proceed to execution. Ask for a final check and wait for my confirmation to start.
- Whenever updating code, ensure that steps below 'PROPOSED IMPLEMENTATION STEPS' are always updated as well.
- Every step in PROPOSED IMPLEMENTATION STEPS MUST have a status tag. Use [COMPLETED] for finished steps, [IN PROGRESS] for current work, or [] for pending steps. When updating PROPOSED IMPLEMENTATION STEPS, ALWAYS verify all steps have status tags and update them based on actual progress.
- To make sure we are done with the current step NEVER PROCEED TO THE NEXT STEP BEFORE I TELL YOU SO.

