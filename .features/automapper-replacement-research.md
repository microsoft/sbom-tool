# AutoMapper Replacement Research

> **Context:** sbom-tool is being deprecated. We need to remove the AutoMapper dependency
> with minimal changes and minimal regression risk.

---

## 0. CVE / Action Item Details

| Field | Value |
|-------|-------|
| **CVE** | **CVE-2026-32933** |
| **Severity** | High |
| **Vulnerable Component** | `automapper 10.1.1` (NuGet) |
| **SLA State** | InSla |
| **Due Date** | 2026-06-12 |
| **Alert ID** | 399814 |
| **Work Item** | [ADO #2367204](https://dev.azure.com/mseng/b924d696-3eae-4116-8443-9a18392d8544/_workitems/edit/2367204) |
| **CG Alert** | [Alert 399814](https://dev.azure.com/mseng/b924d696-3eae-4116-8443-9a18392d8544/_componentGovernance/845?alertId=399814&branchMoniker=main) |
| **Org** | mseng |
| **Branch** | main |

### Affected csproj files in `microsoft/sbom-tool`

| File | Alert ID |
|------|----------|
| `src/Microsoft.Sbom.Api/Microsoft.Sbom.Api.csproj` | 399814 |
| `src/Microsoft.Sbom.DotNetTool/Microsoft.Sbom.DotNetTool.csproj` | 399814 |
| `src/Microsoft.Sbom.Tool/Microsoft.Sbom.Tool.csproj` | 399814 |
| `src/Microsoft.Sbom.Extensions.DependencyInjection/Microsoft.Sbom.Extensions.DependencyInjection.csproj` | 399814 |

> **Note:** The same CVE also affects `microsoft/dropvalidator` (alert 399778, work item
> #2367203) in 3 additional csproj files. A separate `.NET SDK 8.0` security alert
> (DOTNET-Security-8.0, due 2026-05-20) also exists for `global.json`.

---

## 1. Current AutoMapper Footprint

### Packages (Directory.Packages.props)

| Package | Version |
|---------|---------|
| `AutoMapper` | 10.1.1 |
| `AutoMapper.Extensions.Microsoft.DependencyInjection` | 8.1.1 |

### Projects that reference AutoMapper directly (4 of 21)

| Project | What it uses |
|---------|-------------|
| `Microsoft.Sbom.Api` | Core `AutoMapper` — `ConfigurationProfile : Profile`, value converters, `ConfigPostProcessor : IMappingAction` |
| `Microsoft.Sbom.Extensions.DependencyInjection` | `AutoMapper.Extensions.Microsoft.DependencyInjection` — `AddAutoMapper()` in DI registration |
| `Microsoft.Sbom.Tool` | `AutoMapper.Extensions.Microsoft.DependencyInjection` (transitive need) |
| `Microsoft.Sbom.DotNetTool` | `AutoMapper.Extensions.Microsoft.DependencyInjection` (transitive need) |

### What AutoMapper actually does in this codebase

AutoMapper is used for **one single purpose**: converting CLI arguments and config-file
settings into the unified `InputConfiguration` object that the rest of the tool consumes.

**There is exactly 1 AutoMapper Profile** (`ConfigurationProfile`) with these mappings:

| # | Source → Destination | Complexity |
|---|---|---|
| 1 | `ValidationArgs → InputConfiguration` | `.ForMember` ignores (13) |
| 2 | `FormatValidationArgs → InputConfiguration` | `.ForMember` ignores (18) |
| 3 | `GenerationArgs → InputConfiguration` | `.ForMember` ignores (5) |
| 4 | `RedactArgs → InputConfiguration` | `.ForMember` ignores (14) |
| 5 | `AggregationArgs → InputConfiguration` | Simple/no custom logic |
| 6 | `ConfigFile → InputConfiguration` | `.ForMember` ignores (2) |
| 7 | `InputConfiguration → InputConfiguration` | Merge w/ `ConfigPostProcessor` + `ForAllMembers` conflict detection |

Plus **1 ad-hoc mapping** in `ConfigurationExtensions.ToConfiguration()`:

| # | Source → Destination | Complexity |
|---|---|---|
| 8 | `InputConfiguration → Configuration` | Trivial property copy |

### Key AutoMapper features being leveraged

1. **Convention-based property mapping** — matching same-named properties between Args
   classes and `InputConfiguration`.
2. **`ForMember(..., o => o.Ignore())`** — suppressing mapping of destination properties
   that don't exist on the source type.
3. **Custom `IValueConverter<TSrc, TDst>`** — 9 converters that wrap raw values
   (`string`, `int`, `bool`, `IList<ManifestInfo>`, etc.) into `ConfigurationSetting<T>`
   with a `SettingSource` tag (`CommandLine`, `JsonConfig`, `Default`).
4. **`ForAllPropertyMaps`** — global rules that apply the right converter based on source
   property type.
5. **`ForAllMembers` with condition** — merge logic for `InputConfiguration → InputConfiguration`
   that prevents duplicate keys between CLI and config file.
6. **`AfterMap<ConfigPostProcessor>`** — post-processing hook that runs validation,
   sanitization, and default-value assignment after the merge mapping.

### Call sites (7 production calls, all in 2 files)

**`ConfigurationBuilder.cs`** (6 calls):
```
mapper.Map<InputConfiguration>(validationArgs)        // line 34
mapper.Map<InputConfiguration>(generationArgs)        // line 38
mapper.Map<InputConfiguration>(redactArgs)            // line 42
mapper.Map<InputConfiguration>(formatValidationArgs)  // line 46
mapper.Map<InputConfiguration>(aggregationArgs)       // line 50
mapper.Map<ConfigFile, InputConfiguration>(configFromFile)  // line 62
mapper.Map(commandLineArgs, configFileArgs)            // line 65 (merge)
```

**`ConfigurationExtensions.cs`** (1 ad-hoc call):
```
new MapperConfiguration(cfg => cfg.CreateMap<InputConfiguration, Configuration>())
    .CreateMapper().Map<Configuration>(inputConfig)    // line 54-56
```

### AutoMapper type dependencies in source

| Type | AutoMapper dependency |
|------|---------------------|
| `ConfigurationProfile` | Inherits `AutoMapper.Profile` |
| `ConfigPostProcessor` | Implements `AutoMapper.IMappingAction<IConfiguration, IConfiguration>` |
| 9 Value Converters | Implement `AutoMapper.IValueConverter<TSrc, TDst>` (use `ResolutionContext`) |
| `ConfigurationBuilder<T>` | Constructor-injects `AutoMapper.IMapper` |
| `ConfigurationExtensions` | Creates `MapperConfiguration` inline |
| `ServiceCollectionExtensions` | Calls `AddAutoMapper()` extension |

---

## 2. Replacement Options Evaluation

### Option A: Manual Mapping Methods (⭐ RECOMMENDED)

**Approach:** Replace `ConfigurationProfile` + `IMapper` with a single static class
`ConfigurationMapper` containing hand-written mapping methods.

**What changes:**

| File | Change |
|------|--------|
| New: `ConfigurationMapper.cs` | Static methods: `MapToInputConfiguration(ValidationArgs)`, etc. (7 methods + 1 merge method) |
| `ConfigurationBuilder.cs` | Replace `IMapper` injection with `ConfigurationMapper` static calls |
| `ConfigurationExtensions.cs` | Replace ad-hoc `MapperConfiguration` with direct property copy |
| `ConfigPostProcessor.cs` | Remove `IMappingAction` interface, keep as plain class called explicitly |
| 9 Value Converter files | Convert to plain static helper methods (remove `IValueConverter`, `ResolutionContext`) |
| `ConfigurationProfile.cs` | **Delete** |
| `ServiceCollectionExtensions.cs` | Remove `AddAutoMapper()` call |
| 4 `.csproj` files | Remove AutoMapper package references |
| `Directory.Packages.props` | Remove 2 AutoMapper version entries |
| Test files | Replace `MapperConfiguration` setup with direct `ConfigurationMapper` calls |

**Lines of production code changed:** ~250–350 (mapping logic stays identical, just moves
from AutoMapper DSL to C# method bodies)

**Pros:**
- **Zero new dependencies** — nothing to add, only removing
- **Trivially auditable** — every mapping is explicit C# code, easy to verify 1:1
  equivalence with existing `ConfigurationProfile`
- **No source generators or build magic** — works with existing strict build settings
- **No public API break** — `ConfigurationProfile` is public but unlikely to be consumed
  externally; even so, replacing it with a public `ConfigurationMapper` preserves
  functionality

**Cons:**
- Most code to write of all options (but it's mechanical and can be generated from
  existing `ConfigurationProfile`)
- Need to manually maintain ignore lists (but the codebase is EOL, so no new properties)

**Risk:** 🟢 LOW — The mapping logic is simple (property copy + wrapping in
`ConfigurationSetting<T>`). The `.ForMember` ignore directives translate to simply
not mapping those properties. The `ForAllMembers` condition becomes an explicit if-check
in the merge method.

---

### Option B: Mapperly (Source Generator)

**Approach:** Replace AutoMapper with [Mapperly](https://github.com/riok/mapperly), a
compile-time source generator that produces mapping code at build time.

**What changes:**

| File | Change |
|------|--------|
| New: `ConfigurationMapper.cs` | Partial class with `[Mapper]` attribute, `[MapperIgnoreTarget]` attributes on ignored members |
| `ConfigurationBuilder.cs` | Replace `IMapper` with `ConfigurationMapper` instance |
| `ConfigurationExtensions.cs` | Use generated mapper |
| `ConfigPostProcessor.cs` | Remove `IMappingAction`, call explicitly after mapping |
| 9 Value Converter files | Rewrite as `AfterMap` logic or custom type converters using Mapperly's `[UserMapping]` |
| `ConfigurationProfile.cs` | **Delete** |
| `ServiceCollectionExtensions.cs` | Remove `AddAutoMapper()`, register `ConfigurationMapper` |
| `.csproj` files | Replace AutoMapper with `Riok.Mapperly` |
| `Directory.Packages.props` | Swap package references |

**Pros:**
- Less hand-written code than Option A — Mapperly generates the property copying
- Compile-time validation of mappings (fails build if types mismatch)
- High performance (no reflection at runtime)

**Cons:**
- **Adds a new dependency** (Riok.Mapperly) — counter to goal of simplifying an EOL tool
- **Complex converter logic is hard to express** — the `ForAllPropertyMaps` + type-based
  converter dispatch in `ConfigurationProfile` is non-trivial to replicate in Mapperly
- **Source generators + strict build config** — project uses `TreatWarningsAsErrors`,
  `EnforceCodeStyleInBuild`, StyleCop analyzers; source generator interactions may
  require suppressing new warnings
- The `ForAllMembers` conditional merge logic with `ISettingSourceable` check has no
  Mapperly equivalent — must be hand-written anyway
- **Not currently used** — introduces unfamiliar tooling to a codebase that is winding down

**Risk:** 🟡 MEDIUM — Source generator integration risks + need to hand-write the
complex merge logic anyway + new dependency for an EOL project.

---

### Option C: Mapster

**Approach:** Replace AutoMapper with [Mapster](https://github.com/MapsterMapper/Mapster),
a similar runtime reflection-based mapper.

**What changes:**

| File | Change |
|------|--------|
| `ConfigurationProfile.cs` | Rewrite as `TypeAdapterConfig` registration |
| `ConfigurationBuilder.cs` | Replace `IMapper.Map<T>()` with `.Adapt<T>()` |
| `ConfigurationExtensions.cs` | Replace with `.Adapt<Configuration>()` |
| `ConfigPostProcessor.cs` | Rewrite as Mapster `AfterMapping` hook |
| 9 Value Converter files | Rewrite as Mapster `MapWith` or custom converters |
| `ServiceCollectionExtensions.cs` | Replace `AddAutoMapper()` with Mapster registration |
| `.csproj` / `Directory.Packages.props` | Swap packages |

**Pros:**
- API is similar to AutoMapper — lower learning curve for the migration
- Supports `Ignore()`, `AfterMapping()`, conditional mapping

**Cons:**
- **Swaps one reflection-based mapper for another** — resolves CVE-2026-32933 (which is
  specific to the AutoMapper package), but still carries a runtime reflection dependency
- **Adds a new dependency** to an EOL tool
- Less mature ecosystem than AutoMapper
- Complex `ForAllPropertyMaps` / type-based converter dispatch may not translate cleanly

**Risk:** 🟡 MEDIUM — Swapping mappers is not simpler than just writing the code manually.
You still need to learn Mapster's config API and validate every mapping works identically.

---

### Option D: Mapperly Code-Gen Only (Hybrid)

**Approach:** Use Mapperly's source generator as a one-time code generation step during
development, then remove Mapperly and keep only the generated code.

**What changes:**
1. Temporarily add Mapperly, define mapper, build once to get generated `.cs` files
2. Copy generated files into the project as regular source
3. Remove Mapperly package reference
4. Hand-write the complex merge + converter logic
5. End result is same as Option A but with less manual typing

**Pros:**
- Faster initial mapping code generation
- No permanent dependency
- Generated code is auditable

**Cons:**
- Two-step process (generate then clean up)
- Still need to manually handle complex converter/merge logic
- Overkill — the mapping surface is small enough to write by hand in ~1 hour

**Risk:** 🟢 LOW — Same end state as Option A.

---

## 3. Comparison Matrix

| Criterion | A: Manual | B: Mapperly | C: Mapster | D: Hybrid |
|-----------|-----------|-------------|------------|-----------|
| **New dependencies** | 0 | 1 | 1 | 0 |
| **Lines of code changed** | ~300 | ~200 | ~250 | ~300 |
| **Mapping complexity fit** | ✅ Full control | ⚠️ Partial (merge logic manual) | ⚠️ Partial (converter dispatch) | ✅ Full control |
| **Build system risk** | None | Source gen + strict build | None | None |
| **Regression risk** | Low | Medium | Medium | Low |
| **Time to implement** | 2-4 hrs | 3-5 hrs | 3-5 hrs | 2-4 hrs |
| **Maintenance burden** | Lowest (no lib) | Low (compile-time) | Medium (runtime) | Lowest (no lib) |
| **Suitable for EOL tool** | ⭐ Best | Acceptable | Poor | Good |

---

## 4. Recommendation

**Option A (Manual Mapping)** is the clear winner for an end-of-life tool:

1. **Smallest blast radius** — only removes code + adds equivalent explicit code
2. **Zero new dependencies** — simplifies the dependency tree
3. **Most auditable** — every mapping is plain C# that can be diff'd against the
   AutoMapper configuration to verify equivalence
4. **No build system changes** — no source generators, no new analyzer warnings
5. **Easiest to test** — the existing tests already exercise the mapping behavior
   end-to-end; they just need the DI/setup lines updated

### Implementation sketch

```csharp
// New file: ConfigurationMapper.cs
public static class ConfigurationMapper
{
    public static InputConfiguration MapFrom(ValidationArgs args)
    {
        return new InputConfiguration
        {
            BuildDropPath        = WrapString(args.BuildDropPath, SettingSource.CommandLine),
            ManifestDirPath      = WrapString(args.ManifestDirPath, SettingSource.CommandLine),
            Parallelism          = WrapInt(args.Parallelism, SettingSource.CommandLine),
            // ... map each shared property from ValidationArgs
            // Properties that were in ForMember(.Ignore()) are simply not set here
        };
    }

    // Similar methods for GenerationArgs, RedactArgs, FormatValidationArgs,
    // AggregationArgs, ConfigFile

    public static InputConfiguration Merge(InputConfiguration cmdLine, InputConfiguration configFile)
    {
        // Replicate the ForAllMembers condition logic:
        // For each property, if both are non-default, throw.
        // Otherwise, prefer the non-default value.
        // Then call ConfigPostProcessor.Process()
    }

    // Helper wrapping methods (replacing IValueConverter implementations)
    private static ConfigurationSetting<string> WrapString(string value, SettingSource source)
        => string.IsNullOrEmpty(value) ? null : new() { Value = value, Source = source };
    // ... etc for int, bool, etc.
}
```

---

## 5. Test Coverage Assessment — Regression Safety Net

### Existing test infrastructure

| Test project | AutoMapper relevance | Count |
|---|---|---|
| `Microsoft.Sbom.Api.Tests` | **Primary** — directly tests `ConfigurationBuilder` with real mapper | ~29 tests |
| `Microsoft.Sbom.Tool.Tests` | **Integration** — exercises full pipeline including arg parsing → config | ~10 tests |
| `Microsoft.Sbom.Targets.E2E.Tests` | **E2E** — full SBOM generation workflow | ~5 tests |
| 6 other test projects | No direct AutoMapper usage | ~100+ tests |

### Coverage by mapping type

| Mapping | Unit tests | Integration/E2E | Coverage |
|---------|-----------|-----------------|----------|
| `ValidationArgs → InputConfiguration` | ✅ 7 tests (ConfigurationBuilderTestsForValidation) | ✅ IntegrationTests | **Strong** |
| `GenerationArgs → InputConfiguration` | ✅ 11 tests (ConfigurationBuilderTestsForGeneration) | ✅ IntegrationTests | **Strong** |
| `RedactArgs → InputConfiguration` | ✅ 2 tests (ConfigurationBuilderTestsForRedact) | ✅ IntegrationTests | **Good** |
| `FormatValidationArgs → InputConfiguration` | ❌ No dedicated unit tests | ⚠️ E2E only | **Weak** |
| `AggregationArgs → InputConfiguration` | ❌ No dedicated unit tests | ⚠️ E2E only | **Weak** |
| `ConfigFile → InputConfiguration` | ✅ Tested indirectly in all ConfigurationBuilder tests | ✅ | **Good** |
| `InputConfiguration → InputConfiguration` (merge) | ✅ Tested via CombinesConfigs, DuplicateConfig tests | ✅ | **Strong** |
| `InputConfiguration → Configuration` | ❌ No direct tests | ⚠️ Implicit | **Weak** |
| Value converters (9 classes) | ❌ No isolated unit tests | ⚠️ Exercised indirectly | **Weak** |
| `ConfigPostProcessor` | ✅ Exercised through ConfigurationBuilder tests | ✅ | **Good** |

### Test infrastructure detail

The test base class `ConfigurationBuilderTestsBase` creates a **real AutoMapper instance**
(not a mock):

```csharp
var mapperConfiguration = new MapperConfiguration(cfg =>
{
    cfg.ConstructServicesUsing(Ctor);
    cfg.AddProfile<ConfigurationProfile>();
});
mapper = mapperConfiguration.CreateMapper();
```

This means tests are **behavioral tests** — they verify that given certain input args,
the output `InputConfiguration` has the correct values. This is **exactly what we need**
for validating the replacement: the tests don't care about the mapping mechanism, only
the result.

### Gaps and risks

| Gap | Risk | Mitigation |
|-----|------|-----------|
| `FormatValidationArgs` mapping has no unit tests | MEDIUM — if we mismap a property, only E2E catches it | Write 1-2 unit tests before replacing (or carefully audit the manual mapping) |
| `AggregationArgs` mapping has no unit tests | MEDIUM — same as above | Same mitigation; this mapping is the simplest (no ignores) |
| Value converters have no isolated tests | LOW — they're trivial wrapping logic, and are exercised indirectly by every ConfigurationBuilder test | Verify wrapping helpers against converter source code |
| `InputConfiguration → Configuration` has no direct test | LOW — it's a simple same-name property copy | Add one simple test or audit manually |
| `ConfigPostProcessor` relies on `IMappingAction` interface | LOW — just remove the interface, keep the `Process()` method, call it explicitly | Existing tests cover the behavior |

### Overall assessment

> **The existing test suite provides ~70-75% coverage of the mapping behavior.**
>
> The **well-tested paths** (Validation, Generation, Redact, merge, post-processing)
> are the most complex and most important. The **gaps** (FormatValidation, Aggregation,
> value converters in isolation) are either simple mappings or are indirectly covered
> by E2E tests.
>
> **For an EOL tool doing Option A (manual mapping), the existing tests are sufficient
> to catch regressions**, provided:
>
> 1. All existing tests pass after the change (this is the primary validation gate)
> 2. The manual mapping code is audited property-by-property against `ConfigurationProfile`
> 3. Optionally: add 1-2 lightweight tests for `FormatValidationArgs` and `AggregationArgs`

---

## 6. Implementation Checklist (Option A)

If proceeding with manual mapping:

- [ ] Create `ConfigurationMapper` static class with mapping methods for each Args type
- [ ] Create helper methods for value wrapping (replacing the 9 `IValueConverter` classes)
- [ ] Implement `Merge()` method replicating the `ForAllMembers` condition logic
- [ ] Refactor `ConfigPostProcessor` to remove `IMappingAction<>` interface; keep as
      plain class with `Process(IConfiguration, IConfiguration)` method
- [ ] Implement `ToConfiguration()` as direct property copy (replacing ad-hoc
      `MapperConfiguration`)
- [ ] Update `ConfigurationBuilder<T>` to use `ConfigurationMapper` instead of `IMapper`
- [ ] Update `ServiceCollectionExtensions` to remove `AddAutoMapper()` and register
      `ConfigPostProcessor` directly
- [ ] Remove AutoMapper package references from all 4 `.csproj` files
- [ ] Remove AutoMapper entries from `Directory.Packages.props`
- [ ] Update test base class to use `ConfigurationMapper` instead of `MapperConfiguration`
- [ ] Delete `ConfigurationProfile.cs`
- [ ] Delete the 9 value converter files (logic moved to helpers)
- [ ] Run all existing tests — must be 100% green
- [ ] Optional: add unit tests for `FormatValidationArgs` and `AggregationArgs` mapping
