# SBOM API Reference

Users can use the C#-based SBOM API for calling the SBOM tool. This guide is intended to assist users in integrating the SBOM tool API package in a .NET project.

## Prerequisites

* A .NET project that can ingest packages from nuget.org.
* Only projects that target .NET 6 or higher. This API currently provides no support for implementation of .NET Framework for the SBOM API.
* Add the **SBOMToolsPublic** repository to the nuget.config.  Verify the project configuration by clicking the **'Connect to Feed'** button on the feed page [here](https://dev.azure.com/mseng/PipelineTools/_artifacts/feed/SBOMToolsPublic)

## Installation

Add a reference to the [Microsoft.Sbom.Api](https://www.nuget.org/packages/Microsoft.Sbom.Api) package configuration by utilizing the steps posted to [here](https://www.nuget.org/packages/Microsoft.Sbom.Api).  A sample `.csproj` file" is:

```
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.Sbom.Api" Version="1.6.2" />
  </ItemGroup>

</Project>
```

## Getting started

The main entry point for the SBOM generator is in the `SBOMGenerator` class. In order to create an instance of the SBOMGenerator class there are a few arguments that need to be provided. These arguments can be resolved through the dependency injection framework. The following code snippet shows one way to create an instance of the SBOMGenerator class using the dependency injection framework in a pattern that is common when using this approach. Note that this approach is not the only one which will work. For example, if you'd like to avoid implementing the `IHostedService` interface, it should be possible to create a ServiceCollection without using ASP.NET as well.

Following our suggested approach, you can create a Host and add a hosted service that will call the SBOM API along with its dependencies. By calling `.AddSbomTool()` on the service collection, the SBOM API will be added to the dependency injection framework and can be resolved by the hosted service. The hosted service can then be started by calling `RunConsoleAsync` on the host.

```C#
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Extensions.DependencyInjection;

namespace SBOMApiExample;
class Program
{
    public static async Task Main(string[] args)
    {
        await Host.CreateDefaultBuilder(args)
            .ConfigureServices((host, services) =>
            {
                services
                .AddHostedService<GenerationService>()
                .AddSbomTool();
            })
            .RunConsoleAsync(x => x.SuppressStatusMessages = true);
    }
}
```

Now that the entry point is set up, we can define the hosted service. In this example, we will use the `GenerationService` class (This class is user defined) as the hosted service. The `GenerationService` class will be responsible for calling the SBOM API and generating the SBOM.
The following snippet shows how to set up the `GenerationService` class so that arguments are resolved through DI.

In this approach, your class must implement the `IHostedService` interface and provide an implementation for the `StartAsync` and `StopAsync` methods. Now you can pass an instance of the `ISBOMGenerator` interface to the constructor of your class. This interface is provided by the SBOM API and can be resolved by the DI framework. The `ISBOMGenerator` interface provides the methods to generate the SBOM.

Descriptions of the arguments to the `GenerateSbomAsync` method can be found [here](#scan-based-sbom-generator-api) and [here](#self-provided-data-based-sbom-generator-api) and can be defined anywhere necessary as long as they are passed to the `GenerateSbomAsync` method.

```C#
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Contracts;

namespace SBOMApiExample
{
    public class GenerationService: IHostedService
    {
        private readonly ISBOMGenerator generator;
        private readonly IHostApplicationLifetime hostApplicationLifetime;
        public GenerationService(ISBOMGenerator generator, IHostApplicationLifetime hostApplicationLifetime)
        {
            this.generator = generator;
            this.hostApplicationLifetime = hostApplicationLifetime;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var result = await generator.GenerateSbomAsync(rootPath: scanPath,
                                           componentPath: componentPath,
                                           metadata: metadata,
                                           runtimeConfiguration: configuration,
                                           manifestDirPath: sbomOutputPath);

            hostApplicationLifetime.StopApplication();
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
```

The generator object provides two different API implementations for creating the SBOM file - [scan based](#scan-based-sbom-generator-api) and [self provided data based](#self-provided-data-based-sbom-generator-api).

Below are 2 additional helper methods.

### GetSupportedSBOMSpecifications

The `SBOMSpecification` object represents a SBOM format. Each `SBOMSpecification` contains a `name` and a `version`. This structure defines a single format of SBOM.  Sample SPDX version 2.2 format representations include:

```C#
using Microsoft.Sbom.Contracts;

var spdx22Specification = new SBOMSpecification("SPDX", "2.2");
```

While this API supports the creation of a SBOM output file in multiple formats, it currently only supports the SPDX version 2.2 architecture. Users looking to implement other SBOM architectures can use this API call, which provides the full list of all supported formats.

```C#
using Xunit;

var specifications = generator.GetSupportedSBOMSpecifications();

Assert.True(specifications.Count() == 1);
Assert.Equal("SPDX", specifications.First().Name);
Assert.Equal("2.2", specifications.First().Version);
```

### GetRequiredAlgorithms

Each SBOM specification has a list of the required hash algorithms for generating each package and file. This handy API provides the user with that list of hashing algorithms.

```C#

var algorithms = generator.GetRequiredAlgorithms(spdx22Specification);

Assert.True(algorithms.Count() == 2);
Assert.True(algorithms.Any(a => a.Name == "SHA256"));
Assert.True(algorithms.Any(a => a.Name == "SHA1"));
```

This API is a useful tool when utilizing the self-provided data-based API. The API caller will need to supply these hashes for all the packages and files being sent as part of the input data.

## Prerequisites for calling the API

In order to call the API, the user must first include a minimum of one required object and one optional data object.

### SBOM Metadata

The `SBOMMetadata` object provides the API with additional metadata for use in configuring output metadata values in the SBOM file, e.g., product name or version:

```C#
SBOMMetadata metadata = new SBOMMetadata()
{
    PackageName = "MyProject", //Required
    PackageVersion = "0.0.1", // Required
    PackageSupplier = "Contoso", // Required
    BuildId = "2344", // Optional
    BuildEnvironmentName = "Github Actions" // Optional
};
```

The metadata object **must** be created and passed to the API as it contains two required values needed for the SBOM generator to run (i.e., the package name and version). The API uses these values in the generated SBOM files in order to define the name and documentNamespace. Since the other keys in the metadata object are optional, the API may or may not use these values in order to generate additional metadata in the output SBOM file.

### RuntimeConfiguration

The `RuntimeConfiguration` object contains details on the configuration that affects the runtime execution of the API. Configurations such as Verbosity can directly impact the extent or quality of the tool's logging output file.

```C#
RuntimeConfiguration configuration = new RuntimeConfiguration()
{
    DeleteManifestDirectoryIfPresent = true,
    WorkflowParallelism = 8,
    Verbosity = System.Diagnostics.Tracing.EventLevel.Verbose,
    NamespaceUriBase = "http://sbom.mycompany.com"
};
```

The whole `RuntimeConfiguration` object is optional.  As needed, the user can provide a null value to the API.

## Scan-based SBOM generator API

The scan-based SBOM generator API is very similar to the CLI-based tool.  This API uses source directories as parameters.  After scanning the directories for components, the API generates the output SBOM file.

```C#
var result = await generator.GenerateSbomAsync(rootPath: scanPath,
                                               componentPath: componentPath,
                                               metadata: metadata,
                                               runtimeConfiguration: configuration,
                                               manifestDirPath: sbomOutputPath);

Assert.True(result.IsSuccessful);
Assert.False(result.Errors.Any());
```

* The `rootPath` dictates the destination path for publishing the build artifacts. The API will scan all files in 'rootPath' and will subsequently add them to the 'files' section in the SBOM output file. If the command does not include the `manifestDirPath` parameter, the tool will generate the SBOM inside the default `_manifest` folder.
* The `componentPath` parameter normally contains the source folder, which the API will search for dependency components. The 'packages' section in the SBOM file will list the discovered components.

* The `metadata` and `configuration` parameters accept the [`SBOMMetadata`](#sbommetadata) and [`RuntimeConfiguration`](#runtimeconfiguration) objects respectively.
* As desired, the `manifestDirPath` parameter allows users to specify a full folder path if they want the API to save the SBOM to a directory other than the default `_manifest` location.  The API will store the SBOM file in the `_manifest` subfolder under the user-specified path.

The API asynchronously returns a `SBOMGenerationResult` object. A successful SBOM file generation will set the `IsSuccessful` flag value to `true`.  A failed generation run will add the errors to the `Errors` list.

## Self-provided data-based SBOM generator API

There might be occasions where users do not want the API to scan for the target components.  The self-provided data-based API is an ideal choice for those scenarios where users have the list of files and packages for inclusion in the SBOM file.  The self-provided data-based SBOM generator API gives users the ability to serialize the data in the desired format.

Users will still have to provide the metadata and runtime objects for this API.

### SBOMFile

`Path` and `Checksum` are the only required properties for use in the `SBOMFile` object in order to represent a file inside the SBOM.  The API will serialize any additional values unchanged "as-is" in the output SBOM file.

```C#
var file = new SBOMFile
{
    Path = "./tmp/file2.txt",
    Checksum = new List<Checksum>
    {
        new Checksum { Algorithm = AlgorithmName.SHA1, ChecksumValue = "<checksum>" },
        new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "<checksum>" },
    }
};
```

The API looks for a relative path starting with a period `.`.  All path separators should include forward slashes `/` in compliance with the SPDX version 2.2 specification.

### SBOMPackage

'SBOMPackage' represents a dependency component for the product. The `PackageName` is the only required property. The API will serialize all other properties unchanged "as-is" in the final output SBOM file.

```C#
var package = new SBOMPackage
{
    PackageName = "com.test.Foo",
    
};
```

You can call the API as shown below:

```C#
using Microsoft.Sbom.Contracts.Enums;

var result = await generator.GenerateSBOMAsync(rootPath: scanPath,           
                                               files: sbomFiles,
                                               packages: sbomPackages,
                                               metadata: metadata,
                                               runtimeConfiguration: configuration,
                                               manifestDirPath: sbomOutputPath);
```

* The `rootPath` specifies the path for placing the output SBOM file. User specifying the destination path with the `manifestDirPath` parameter can  utilize the `null` value for `rootPath`.
* The `files` parameter contains a list of `SBOMFile` objects.
* The `packages` parameter contains a list of `SBOMPackage` objects.
* The `metadata` and `runtimeConfiguration` parameters accept the [`SBOMMetadata`](#sbommetadata) and [`RuntimeConfiguration`](#runtimeconfiguration) objects (respectively).
* If users want the API to generate the output SBOM in a different folder other the default location, they need to provide the path in the `manifestDirPath` parameter. Users will find the SBOM file under the `_manifest` directory at the user-specified path.

## SBOM Validation

Now that you have generated the SBOM file, you can validate it using the `SBOMValidator` class. Setup for this will be very similar to the `SBOMGenerator` class. Here is an example:

```C#
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Extensions.DependencyInjection;

namespace SBOMApiExample;
class Program
{
    public static async Task Main(string[] args)
    {
        await Host.CreateDefaultBuilder(args)
            .ConfigureServices((host, services) =>
            {
                services
                .AddHostedService<ValidationService>()
                .AddSbomTool();
            })
            .RunConsoleAsync(x => x.SuppressStatusMessages = true);
    }
}
```

After the Host is set up, you can inject the `ISBOMValidator` interface into your service and use it to validate the SBOM file. Here is an example:
Note that the only arguments required are the `buildDropPath`,  the `outputPath`, and the `SbomSpecification`. The `buildDropPath` is the path to the directory containing the _manifest directory. The `outPath` is the path to the file where the validation output will be written. The only `SbomSpecification` currently supported is `SPDX 2.2`.
All other arguments are optional.

```C#
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Contracts;

namespace SBOMApiExample
{
    public class ValidationService : IHostedService
    {
        private readonly ISBOMValidator sbomValidator;
        private readonly IHostApplicationLifetime hostApplicationLifetime;

        public ValidationService(
        ISBOMValidator sbomValidator,
        IHostApplicationLifetime hostApplicationLifetime)
        {
            this.sbomValidator = sbomValidator;
            this.hostApplicationLifetime = hostApplicationLifetime;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            string buildDropPath = "C:/repos/samplePath";
            string outputPath = "C:/temp/ValidationOutput.json";
            IList<SbomSpecification> spdx22Specification = new List<SbomSpecification>()
            {
                new SbomSpecification("SPDX","2.2")
            };

            RuntimeConfiguration configuration = new RuntimeConfiguration()
            {
                Verbosity = System.Diagnostics.Tracing.EventLevel.Information,
            };

            var result = await sbomValidator.ValidateSbomAsync(buildDropPath, outputPath, spdx22Specification, runtimeConfiguration: configuration);

            
            hostApplicationLifetime.StopApplication();
        }
        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

    }
}
```
