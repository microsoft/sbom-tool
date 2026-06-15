---
name: sbom-tool
description: Generate, validate, redact, and aggregate SPDX 2.2 / 3.0 SBOMs for any build artifact using Microsoft's sbom-tool CLI. Use when the user wants to create a software bill of materials, produce an SPDX file, validate an existing SBOM, scan a build drop or source tree (or Docker images) for components, fetch license info, or wire SBOM generation into CI/CD. Triggers: "SBOM", "software bill of materials", "SPDX", "sbom-tool generate/validate/redact/aggregate", "manifest.spdx.json", "component detection for licensing".
---

# sbom-tool

Microsoft's `sbom-tool` is a scalable CLI that produces SPDX 2.2 and SPDX 3.0 SBOMs for any build artifact. It hashes files in a build drop, uses [Component Detection](https://github.com/microsoft/component-detection) to discover dependency packages from source, and optionally enriches packages with license data from the [ClearlyDefined](https://github.com/clearlydefined/clearlydefined) API.

This skill is tool-agnostic — Claude Code, Codex, opencode, or any agent can follow it. Replace `sbom-tool` below with the actual invocation for the install method in use (see Installation).

## When to use this skill

- The user wants to generate an SBOM / SPDX file for a project, build output, or container.
- The user has an SBOM and wants to validate it, redact file references, or aggregate several SBOMs into one.
- The user is integrating SBOM generation into a GitHub Actions or Azure DevOps pipeline.

## Installation (pick one, then use that form everywhere)

| Method | Install | Invoke as |
|--------|---------|-----------|
| Homebrew (macOS/Linux) | `brew install sbom-tool` | `sbom-tool` |
| WinGet (Windows) | `winget install Microsoft.SbomTool` | `sbom-tool` |
| .NET global tool | `dotnet tool install --global Microsoft.Sbom.DotNetTool` | `sbom-tool` |
| Manual binary (Linux) | `curl -Lo sbom-tool https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-linux-x64 && chmod +x sbom-tool` | `./sbom-tool` |
| Manual binary (macOS) | `curl -Lo sbom-tool https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-osx-x64 && chmod +x sbom-tool` | `./sbom-tool` |
| Manual binary (Windows) | download `sbom-tool-win-x64.exe` from Releases | `./sbom-tool-win-x64.exe` |
| Docker | `docker build . -t ms_sbom_tool` (from a clone), then bind-mount dirs | `docker run -v ...` |

Check `sbom-tool --version` to confirm it's on PATH before running a workflow.

## Core mental model

- **Build drop path (`-b`)**: folder of final artifacts (binaries/executables). Every file here is hashed and listed in the SBOM's *files* section.
- **Build components path (`-bc`)**: usually your source tree. Scanned for project files (`*.csproj`, `package.json`, `packages.config`, etc.) to populate the *packages* (dependencies) section.
- **Output**: by default written to `<build-drop>/_manifest/spdx_2.2/manifest.spdx.json` (or `spdx_3.0/` for SPDX 3.0). Override the location with `-m`.
- The tool needs **write access** to the `-b` path (or the `-m` path) to create `_manifest/`.

## Recipe: generate an SBOM

Minimum mandatory arguments:

```shell
sbom-tool generate \
  -b <build drop path> \
  -bc <build components / source path> \
  -pn <package name> \
  -pv <package version> \
  -ps <package supplier> \
  -nsb <namespace URI base>
```

Concrete .NET example (build first, then generate):

```shell
dotnet build --output ./outputDrop
sbom-tool generate -b ./outputDrop -bc . -pn TestProject -pv 1.0.0 -ps MyCompany -nsb https://mycompany.com
```

Notes:
- `-nsb` is the org-wide base of the SPDX document namespace, e.g. `https://companyName.com/teamName`. The tool appends `/<packageName>/<packageVersion>/<new-guid>` to make it globally unique. If omitted, the tool generates a compliant default.
- Generation defaults to **SPDX 2.2**. Add `-mi SPDX:3.0` to produce SPDX 3.0.
- `-pn`/`-pv` can sometimes be inferred from the build, but supply them explicitly to avoid failures.

### Common generate variations

| Goal | Add |
|------|-----|
| Produce SPDX 3.0 | `-mi SPDX:3.0` |
| Write SBOM to a custom folder | `-m <dir>` (creates `<dir>/_manifest/...`) |
| Fetch license info from ClearlyDefined | `-li true` (optionally `-lto <seconds>`) |
| Parse license/supplier from package metadata | `-pm true` |
| Scan Docker images for packages | `-di image:tag` (comma-separate multiple: `-di a:1,b:2`) |
| Exclude dirs from component scan | `-cd "--DirectoryExclusionList **/bin/** --DirectoryExclusionList **/obj/**"` |
| Overwrite existing `_manifest` without prompting | `-D true` |
| Verbose logging | `-V Verbose` |
| Write telemetry to a file | `-t <path>` |
| Limit files to a list | `-bl <file-list.txt>` (one path per line) |

Docker-only example (packages only, empty files section — omit `-b`, use `-m`):

```shell
sbom-tool generate -m ./outputPath -pn TestProject -pv 1.0.0 -ps MyCompany -nsb https://mycompany.com -di testImage:0.0.1
```

> `--DirectoryExclusionList` is a Component Detection argument passed through `-cd`. Repeat the flag for multiple patterns — combined minimatch like `**/bin/**|**/obj/**` does **not** work.

## Recipe: validate an SBOM

```shell
sbom-tool validate -b <build drop path> -o <output results.json> -mi SPDX:2.2
sbom-tool validate -b <build drop path> -o <output results.json> -mi SPDX:3.0
```

- `-b` must be the same path used at generation; the tool looks for `<-b>/_manifest/spdx_2.2/manifest.spdx.json` (or `spdx_3.0/`).
- `-o` is where validation results JSON is written (file path, e.g. `./validation/output.json`).
- `-mi` selects the manifest format/version to validate against.
- If the SBOM was generated to a custom `-m` location, pass `-m <dir>/_manifest` to validation too.
- Useful flags: `-s` validate signature against signed catalog, `-im` ignore files missing on disk, `-n` fail if no packages detected, `-Ha` hash algorithm, `-cs` conformance standard.

## Recipe: redact file references

Removes file references from an SBOM (currently **SPDX 2.2 only**). Output dir must be existing, empty, and different from the source dir.

```shell
sbom-tool redact -sp <path to SBOM> -o <empty output dir>
# or a whole directory of SBOMs:
sbom-tool redact -sd <dir containing SBOMs> -o <empty output dir>
```

## Recipe: aggregate multiple SBOMs

Combines several SBOMs into one (**SPDX 2.2 only**). Requires a config file (`-C`):

```shell
sbom-tool aggregate -C ./config.json
```

```json
{
  "ArtifactInfoMap": {
    "/path/to/Artifact1/bin/Release/net8.0": { },
    "/path/to/Artifact2/bin": { "ExternalManifestDir": "/path/to/Artifact2/_manifest" }
  },
  "ManifestDirPath": "/path/to/output",
  "PackageName": "CombinedPackageName",
  "PackageVersion": "1.0.0",
  "PackageSupplier": "MyCompany"
}
```

Each `ArtifactInfoMap` key points at an artifact dir; the SBOM is expected at `<key>/_manifest/spdx_2.2` unless `ExternalManifestDir` overrides the `_manifest` segment.

## Config file instead of flags

Any command accepts `-C <config.json>` with the arguments as JSON keys. Environment variables in `$(VAR)` form are expanded:

```json
{
  "PackageSupplier": "MyCompany",
  "PackageName": "TestProject",
  "PackageVersion": "1.0.0",
  "BuildDropPath": "$(BUILD_DROP_PATH)",
  "BuildComponentPath": "$(BUILD_COMPONENT_PATH)"
}
```

## CI/CD

- GitHub Actions: see `docs/setting-up-github-actions.md` in this repo.
- Azure DevOps: see `docs/setting-up-ado-pipelines.md`.
- Telemetry: by default written to the output path as JSON; nothing is sent to Microsoft.

## Argument quick reference

`generate`: `-b` build drop, `-bc` components/source, `-bl` file list, `-m` manifest dir, `-pn` name, `-pv` version, `-ps` supplier, `-nsb` namespace base, `-nsu` namespace unique part, `-mi` manifest info (`SPDX:2.2`/`SPDX:3.0`), `-di` docker images, `-cd` extra Component Detection args, `-er` external doc references file, `-gt` generation timestamp, `-D` delete existing manifest dir, `-li` fetch license info, `-lto` license timeout (s), `-pm` parse package metadata, `-P` parallelism, `-F` follow symlinks, `-t` telemetry file, `-V` verbosity.

`validate`: `-b`, `-m`, `-o` output, `-mi`, `-s` validate signature, `-im` ignore missing, `-n` fail if no packages, `-r` root path filter, `-Ha` hash algorithm, `-cs` conformance, `-P`, `-F`, `-t`, `-V`.

`redact`: `-sp` SBOM path, `-sd` SBOM dir, `-o` output dir, `-V`.

`aggregate`: `-C` config file, `-t`, `-V`.

Full help: `sbom-tool generate -h`. Detailed docs live under `docs/` (`sbom-tool-arguments.md`, `sbom-tool-cli-reference.md`).
