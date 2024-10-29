Generates Software Bill of Materials (SBOM)

See [SBOM API Reference](https://github.com/microsoft/sbom-tool/blob/main/docs/sbom-tool-api-reference.md) for details on how to set up a Generation Service using the Microsoft Dependency
Injection Library.

#### Scan Sample
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
            string scanPath = @"D:\tmp\SBOM\";
            string outputPath = @"D:\tmp\SBOM\_manifest";

            SBOMMetadata metadata = new SBOMMetadata()
            {
                PackageName = "MyVpack",
                PackageVersion = "0.0.1"            };

            IList<SBOMSpecification> specifications = new List<SBOMSpecification>()
            {
                new SBOMSpecification ("SPDX", "2.2.2")
            };

            RuntimeConfiguration configuration = new RuntimeConfiguration()
            {
                DeleteManifestDirectoryIfPresent = true,
                WorkflowParallelism = 4,
                Verbosity = System.Diagnostics.Tracing.EventLevel.Verbose,
            };

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

#### If you have files and don't need to scan for them

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
            var result = await generator.GenerateSbomAsync(
                                outputDirectory,
                                sbomFiles,
                                sbomPackages,
                                metadata,
                                new List<SBOMSpecification> { new("SPDX", "2.2.2") },
                                new RuntimeConfiguration { DeleteManifestDirectoryIfPresent = true });

            hostApplicationLifetime.StopApplication();
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
```
