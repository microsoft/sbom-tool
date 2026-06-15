# Copilot instructions for sbom-tool

This repository ships a reusable Agent Skill that documents how to drive the
`sbom-tool` CLI (generate / validate / redact / aggregate SPDX 2.2 & 3.0 SBOMs).

When a task involves running, scripting, or troubleshooting `sbom-tool`, read and
follow the skill at:

- `.claude/skills/sbom-tool/SKILL.md`

GitHub Copilot CLI also auto-discovers that skill via `skillDirectories` in
`.github/copilot/settings.json`, so it loads natively as a skill. The same file
is consumed by Claude Code, Codex, and opencode — keep it as the single source of
truth and edit only `.claude/skills/sbom-tool/SKILL.md`.
