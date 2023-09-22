# SBOM API Reference

The SBOM tool can be called using a C# API. This guide will help you integrate the SBOM tool API package in your .NET project.

## Prerequisites
* You have a .NET project that can ingest packages from nuget.org.
* Only projects that target .NET 6 or higher are supported, we don't have a .NET Framework implementation for the SBOM API. 
* You are using [Microsoft Dependency Injection](https://www.nuget.org/packages/Microsoft.Extensions.DependencyInjection) in your project.
* Add the **SBOMToolsPublic** repository to your nuget.config, you can check the steps to get it added to your project by clicking the **'Connect to Feed'** button on the feed page [here](https://dev.azure.com/mseng/PipelineTools/_artifacts/feed/SBOMToolsPublic)

## Installation

Add a reference to the [Microsoft.Sbom.Api](https://www.nuget.org/packages/Microsoft.Sbom.Api) package in your packages configuration. Please follow the steps [here](https://www.nuget.org/packages/Microsoft.Sbom.Api) to add the package to your project. An example to add the package to your `.csproj` file is shown below

```
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.Sbom.Api" Version="1.6.2" />
  </ItemGroup>

</Project>
```

## Getting started 

The main entry point for the SBOM generator is in the `SBOMGenerator` class. In order to create an instance of the SBOMGenerator class there are a few arguments that need to be provided. These arguments can be resolved 
through the dependency injection framework. The following code snippet shows how to create an instance of the SBOMGenerator class using the dependency injection framework using a pattern that is common when using this approach.

You can create a Host and add a hosted service that will call the SBOM API along with its dependencies. By calling `.AddSbomTool()` on the service collection, the SBOM API will 
be added to the dependency injection framework and can be resolved by the hosted service. The hosted service can then be started by calling `RunConsoleAsync` on the host.

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

Now that the entry point is setup, we can define the hosted service. In this example, we will use the `GenerationService` class (This class is user defined) as the hosted service. The `GenerationService` class will be responsible for calling the SBOM API and generating the SBOM.
The following snippet shows how to set up the `GenerationService` class so that arguments are resolved through DI.

Your class must implement the `IHostedService` interface and provide an implementation for the `StartAsync` and `StopAsync` methods. Now you can pass an instance of the `ISBOMGenerator` interface to the constructor of your class. This interface is provided by the SBOM API and can be resolved by the DI framework. The `ISBOMGenerator` interface provides the methods to generate the SBOM.

Descriptions of the arguments to the `GenerateSbomAsync` method can be found [here](#scan-based-sbom-generator-api) and [here](#self-provided-data-based-sbom-generator-api) and can be defined anywhere needed as long as they are passed to the `GenerateSbomAsync` method.

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
            await Task.Run(async () =>
            {
                var result = await generator.GenerateSbomAsync(rootPath: scanPath,
                                               componentPath: componentPath,
                                               metadata: metadata,
                                               runtimeConfiguration: configuration,
                                               manifestDirPath: sbomOutputPath);
                Console.WriteLine(result);
                hostApplicationLifetime.StopApplication();
            });
        }
        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
```

The generator object provides two different API implementations that can be used to generate the SBOM, [scan based](#scan-based-sbom-generator-api) and [self provided data based](#self-provided-data-based-sbom-generator-api).

It also provides 2 additional helper methods explained below

### GetSupportedSBOMSpecifications

A SBOM format is represented by the `SBOMSpecificiation` object. Each `SBOMSpecification` contains a `name` and a `version`. This structure defines a single format of SBOM, for example, the SPDX 2.2 format can be represented by

```C#
using Microsoft.Sbom.Contracts;

var spdx22Specification = new SBOMSpecification("SPDX", "2.2");
```

Our tool is designed to support multiple formats of SBOM, however it currently only supports SPDX v2.2. If you have additional SBOM formats that are implememnted, this handy API call can provide you with a list of all the formats that are currently supported by our tool.

```C#
using Xunit;

var specifications = generator.GetSupportedSBOMSpecifications();

Assert.True(specifications.Count() == 1);
Assert.Equal("SPDX", specifications.First().Name);
Assert.Equal("2.2", specifications.First().Version);
```

### GetRequiredAlgorithms

Each SBOM specification has a list of hash algorithms that are required to be generated for each package and file. This handy API will provide a list of hashing algorithms that are required for a specific SBOM format.

```C#

var algorithms = generator.GetRequiredAlgorithms(spdx22Specification);

Assert.True(algorithms.Count() == 2);
Assert.True(algorithms.Any(a => a.Name == "SHA256"));
Assert.True(algorithms.Any(a => a.Name == "SHA1"));

```

This API is helpful when using the self provided data based API, as the caller would have to provide these hashes for all the packages and files they send as part of the input data.

## Prerequisites for calling the API

In order to call the API, you must first generate one required and one optional data object.

### SBOMMetadata

The `SBOMMetadata` object provides the SBOM tool with additional metadata that can be used to configure some output metadata values in the SBOM, for example the product name or version.

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

The metadata object **must** be created and passed to the API as it contains two required values for the SBOM generator to run, the package name and version. These values are used in the generated SBOM to define the name and documentNamespace. The other keys in the metadata object are optional, and the tool may or may not use these values to generate additional metadata in the created SBOM.


### RuntimeConfiguration

The `RuntimeConfiguration` object contains configuration that affects the actual execution of the SBOM tool. It contains configurations like Verbosity that can affect how much logging is returned by our tool. 

```C#
RuntimeConfiguration configuration = new RuntimeConfiguration()
{
    DeleteManifestDirectoryIfPresent = true,
    WorkflowParallelism = 8,
    Verbosity = System.Diagnostics.Tracing.EventLevel.Verbose,
    NamespaceUriBase = "http://sbom.mycompany.com"
};
```

## Scan based SBOM generator API

The scan based SBOM generator API is very similar to the CLI based tool, as in it takes the source directories as parameters, and scans the directories for components and generates the SBOM for you.

```C#

var result = await generator.GenerateSbomAsync(rootPath: scanPath,
                                               componentPath: componentPath,
                                               metadata: metadata,
                                               runtimeConfiguration: configuration,
                                               manifestDirPath: sbomOutputPath);

Assert.True(result.IsSuccessful);
Assert.False(result.Errors.Any());
```

* The `rootPath` here is the path where your build artifacts that are to be published live. All the files here will be scanned and added to the 'files' section in the SBOM. If the `manifestDirPath` parameter is not provided, the generated SBOM will also be placed here inside the `_manifest` folder.
* The `componentPath` parameter usually contains your source folder, and it will be searched for dependency compenents. All the discovered components will end up in the 'packages' section in the SBOM. This parameter is optional, and if not provided, the SBOM will not contain any packages.
* The `metadata` and `configuration` parameters accept the [`SBOMMetadata`](#sbommetadata) and [`RuntimeConfiguration`](#runtimeconfiguration) objects respectively.
* In case you want the generated SBOM to be placed in a different folder, you can provide the path in the `manifestDirPath` parameter. Please note, we will generate a `_manifest` directory at this path and store the SBOMs there.

The API is asynchronous and it returns a `SBOMGenerationResult` object. If the generation was successful, the `IsSuccessful` flag is set to `true`. If the generation failed, the errors will be added to the `Errors` list.
## Self provided data based SBOM generator API

There might be occasions where you don't want us to scan for your components, and you already have the list of files and packages you want to include in the SBOM and want to use our tool only to serialize the data in the right format, the self provided data based API is the choice for you.

You will still have to provide the metadata and runtime objects for this API.

### SBOMFile

A file inside the SBOM is represented using the `SBOMFile` object. `Path` and `Checksum` are the only required properties, any additional values will be serialized as is to the final SBOM. 

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

The path should be a relative path and should start with a period `.`, and all the path seperators should be forward slashes `/` to comply with the SPDX 2.2 specification.


### SBOMPackage

The SBOM package represents a dependency component for your product. The `PackageName` is the only required property. All other properties will be serialized as is to the output SBOM.

```C#

var package = new SBOMPackage
{
    PackageName = "com.test.Foo",
    
};
```

You can call the API as shown below.

```C#
using Microsoft.Sbom.Contracts.Enums;

var result = await generator.GenerateSBOMAsync(rootPath: scanPath,           
                                               files: sbomFiles,
                                               packages: sbomPackages,
                                               metadata: metadata,
                                               runtimeConfiguration: configuration,
                                               manifestDirPath: sbomOutputPath);
```

* The `rootPath` is the path where the generated SBOM will be placed. If you are providing the `manifestDirPath` parameter to specify the SBOM generation location, you can use a `null` value here.
* The `files` parameter contains a list of `SBOMFile` objects, and the `packages` parameter contains a list of `SBOMPackage` objects. 
* The `metadata` and `runtimeConfiguration` parameters accept the [`SBOMMetadata`](#sbommetadata) and [`RuntimeConfiguration`](#runtimeconfiguration) objects respectively.
* In case you want the generated SBOM to be placed in a different folder, you can provide the path in the `manifestDirPath` parameter. Please note, we will generate a `_manifest` directory at this path and store the SBOMs there.
