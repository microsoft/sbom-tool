# SBOM Generation for .NET Projects
## Microsoft.Sbom.Targets
This project implements a custom MSBuild task that generates an SBOM using the SBOM API and CLI tool. The MSBuild task binaries along with the associated targets are packaged as a NuGet package and can be consumed within a .NET project. Once installed, an SBOM will automatically be generated upon building the .NET project.

## MSBuild Task Implementation
The custom MSBuild task is implemented across the following partial classes:
- `GenerateSbom.cs`
- `GenerateSbomTask.cs`
- `SbomCLIToolTask.cs`
- `SbomInputValidator.cs`

Due to differences in [MSBuild versions](https://learn.microsoft.com/en-us/visualstudio/msbuild/tutorial-custom-task-code-generation?view=vs-2022#create-the-appsettingstronglytyped-project) between Visual Studio and the .Net Core CLI tool, the SBOM generation logic needed to be split into two parts:

1) `GenerateSbomTask.cs` is invoked if the MSBuild version targets the "Core" (.NET Core) runtime bundled with the .NET Core CLI tool. This class utilizes the SBOM API to generate an SBOM.

2) `SbomCLIToolTask.cs` is invoked if the MSBuild version targets the "Full" (.NET Framework) runtime bundled with Visual Studio. Because the SBOM API does not support .NET Framework, this class utilizes the SBOM CLI Tool to generate an SBOM.

Finally, the `Microsoft.Sbom.Targets.targets` file creates a target that will execute the custom MSBuild task. This file will be automatically imported when consuming the NuGet package.

## SBOM Generation Properties
The custom MSBuild task accepts most of the arguments available for the [SBOM CLI Tool](../../docs/sbom-tool-arguments.md). After the .targets file is imported into a .NET project, the following properties can be set:

| Property | Default Value | Required |
|-----------------------------------------------------|-------------|---------|
| `<GenerateSBOM>`                                    | `false`     | No. To enable SBOM generation, set this to true. |
| `<SbomGenerationBuildComponentPath>`                | `$(MSBuildProjectDirectory)` | No | 
| `<SbomGenerationPackageSupplier>`                   | `$(Authors)`. If `$(Authors)` is null, it will set `$(AssemblyName)`     | Yes | 
| `<SbomGenerationPackageName>`                       | `$(PackageId)`. If `$(PackageId)` is null, it will set `$(AssemblyName)` | Yes | 
| `<SbomGenerationPackageVersion>`                    | `$(Version)`. If `$(Version)` is null, it will set "1.0.0"               | Yes | 
| `<SbomGenerationNamespaceBaseUri>`                  | `http://spdx.org/spdxdocs/$(SbomGenerationPackageName)`                  | Yes | 
| `<SbomGenerationNamespaceUriUniquePart>`            | N/A | No | 
| `<SbomGenerationExternalDocumentReferenceListFile>` | N/A | No | 
| `<SbomGenerationFetchLicenseInformation>`           | `false` | No | 
| `<SbomGenerationEnablePackageMetadataParsing>`      | `false` | No | 
| `<SbomGenerationVerbosity>`                         | `Information` | No | 
| `<SbomGenerationManifestInfo>`                      | `SPDX:2.2` | No | 
| `<SbomGenerationDeleteManifestDirIfPresent>`        | `true` | No | 

## Local SBOM Generation Workflow
After building the Microsoft.Sbom.Targets project, it will generate a NuGet package containing the MSBuild task's binaries and associated .targets file in the `bin\$(Configuration)` folder. The following steps describe how to consume this NuGet package and generate an SBOM:

1) Create a sample .NET project.
2) Open the project's NuGet package manager.
3) Add the path to the Microsoft.Sbom.Targets NuGet package as a package source. You can name it "Local". 
4) Look for the Microsoft.Sbom.Targets package within the package manager and install it. 
5) Add the following to your sample project's .csproj file:
```
<PropertyGroup>
  <GenerateSBOM>true</GenerateSBOM>
</PropertyGroup>
```
6) Build the sample project.
7) Pack the sample project. The SBOM will be generated under the `_manifest` folder at the root of the NuGet package.
