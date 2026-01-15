<instructions>

## Required Reading (Every Session)

**At the START of each new chat session**, read these in order:

### 1. Base Rules (CRITICAL)
- [00-base-rules.instructions.md](00-base-rules.instructions.md) — Collaboration workflow (always applies)

### 2. Memory Bank
- [01-memory-bank.instructions.md](01-memory-bank.instructions.md)
- [activeContext.md](../.memory-bank/activeContext.md)
- [learnings.md](../.memory-bank/learnings.md)

</instructions>

# Copilot Instructions for sbom-tool

## Project Overview
SBOM tool is a Microsoft .NET 8.0 cross-platform tool that generates SPDX 2.2 and SPDX 3.0 compatible Software Bill of Materials (SBOM). It uses Component Detection for dependency scanning and ClearlyDefined for license information.

## Architecture

### Project Structure
- `src/Microsoft.Sbom.Api` - Core SBOM generation engine and workflows
- `src/Microsoft.Sbom.Contracts` - Public interfaces (`ISbomGenerator`, `ISbomValidator`, `ISbomAggregator`)
- `src/Microsoft.Sbom.Extensions` - Extension interfaces (`IManifestGenerator`, `ISbomParser`)
- `src/Microsoft.Sbom.Common` - Shared utilities, constants, file system abstractions
- `src/Microsoft.Sbom.Tool` - CLI entry point using `Spectre.Console.Cli` and `PowerArgs`
- `src/Microsoft.Sbom.DotNetTool` - .NET tool packaging
- `src/Microsoft.Sbom.Parsers.Spdx22SbomParser` - SPDX 2.2 format implementation
- `src/Microsoft.Sbom.Parsers.Spdx30SbomParser` - SPDX 3.0 format implementation
- `src/Microsoft.Sbom.Targets` - MSBuild targets for integration
- `test/` - Unit and integration tests using MSTest

### Key Patterns
- Dependency injection via `Microsoft.Extensions.DependencyInjection`
- Workflow pattern: `IWorkflow<T>` interface with implementations like `SbomGenerationWorkflow`
- Configuration flows through `IConfiguration` and `ConfigurationBuilder<T>`
- Extension points use `IManifestGenerator` and `ISbomParser` interfaces

## Code Style

### General Rules
- Target framework: `net8.0`
- Use `LangVersion` latest
- Treat warnings as errors (`TreatWarningsAsErrors=true`)
- Enforce code style in build (`EnforceCodeStyleInBuild=true`)
- Use file-scoped namespaces: `namespace Microsoft.Sbom.Api;`
- Root namespace: `Microsoft.Sbom`

### File Header
Every C# file must start with: `// Copyright (c) Microsoft. All rights reserved.` followed by `// Licensed under the MIT license. See LICENSE file in the project root for full license information.`

### Naming Conventions
- Interfaces: prefix with `I` (e.g., `IManifestGenerator`)
- Type parameters: prefix with `T`
- Private fields: `camelCase`
- Public constants: `PascalCase`
- Classes, methods, properties: `PascalCase`

### Code Preferences
- Use `var` when type is apparent
- Prefer pattern matching over `is`/`as` with null checks
- Use expression-bodied members where appropriate
- Always include accessibility modifiers
- Prefer braces for control statements
- Use null-conditional (`?.`) and null-coalescing (`??`) operators
- Use object/collection initializers

### Async Guidelines
- Suffix async methods with `Async`
- Use `Task` and `Task<T>` return types
- Workflows implement `Task<bool> RunAsync()`

## Testing

### Framework
- MSTest with `[TestClass]` and `[TestMethod]` attributes
- Mocking with `Moq`
- Test projects follow naming: `Microsoft.Sbom.*.Tests`

### Test Conventions
- Test class names match the class being tested with `Tests` suffix
- Test methods use descriptive names: `When_<Scenario>_Then_<Expected>` or `<Method>_<Scenario>_<Expected>`
- Use `Assert.ThrowsException<T>` for expected exceptions
- Use `[DataRow]` for parameterized tests

## Dependency Injection

### Registration Pattern
Services are registered in `AddSbomTool()` extension method. Use constructor injection with null guards:
```csharp
public MyClass(IService service) => this.service = service ?? throw new ArgumentNullException(nameof(service));
```

### Common Services
- `IConfiguration` - Runtime configuration
- `IFileSystemUtils` - File system abstraction
- `IRecorder` - Telemetry recording
- `ISbomConfigProvider` - SBOM format configurations
- `ILogger` - Serilog logging

## Package Management
- Central package management via `Directory.Packages.props`
- Never specify versions in project files
- Key dependencies: `Serilog`, `PowerArgs`, `AutoMapper`, `System.Text.Json`, `Newtonsoft.Json`

## Error Handling
- Use custom exception types from `Microsoft.Sbom.Api.Exceptions`
- Validate arguments with `ArgumentNullException` or `ArgumentException`
- Return `SbomGenerationResult` or similar result types with success status and error lists

## SPDX Specifics
- Support both SPDX 2.2 and SPDX 3.0 formats
- Use `ManifestInfo` to identify SBOM specifications
- Implement `IManifestGenerator` for new format support
- Use `SbomPackage`, `SbomFile`, `SbomRelationship` contract types

## Build Commands
- Build: `dotnet build`
- Test: `dotnet test`
- Run: `dotnet run --project src/Microsoft.Sbom.Tool generate -b <path> -bc <path> -pn <name> -pv <version> -ps <supplier>`

## Common Pitfalls
- Always dispose `JsonDocument` objects returned by generators
- Use `InternalsVisibleTo` with strong name key for test access to internals
- Configuration validation happens through `ConfigValidator` implementations
- File paths should be handled through `IFileSystemUtils` abstraction
