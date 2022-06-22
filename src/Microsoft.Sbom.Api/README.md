Generates Software Bill of Materials (SBOM)

#### Scan Sample
```C#
            var generator = new SBOMGenerator();

            string scanPath = @"D:\tmp\SBOM\";
            string outputPath = @"D:\tmp\SBOM\_manifest";

            SBOMMetadata metadata = new SBOMMetadata()
            {
                PackageName = "MyVpack",
                PackageVersion = "0.0.1"            };

            IList<SBOMSpecification> specifications = new List<SBOMSpecification>()
            {
                new SBOMSpecification ("SPDX", "2.2")
            };

            RuntimeConfiguration configuration = new RuntimeConfiguration()
            {
                DeleteManifestDirectoryIfPresent = true,
                WorkflowParallelism = 4,
                Verbosity = System.Diagnostics.Tracing.EventLevel.Verbose,
            };

            await generator.GenerateSBOMAsync(scanPath, scanPath, metadata, null, configuration, outputPath);
```

#### If you have files and don't need to scan for them

```C#
            SBOMGenerator generator = new();
            Task<SBOMGenerationResult> task = generator.GenerateSBOMAsync(
                outputDirectory,
                sbomFiles,
                sbomPackages,
                metadata,
                new List<SBOMSpecification> { new("SPDX", "2.2") },
                new RuntimeConfiguration { DeleteManifestDirectoryIfPresent = true });

            bool taskCompleted = task.Wait(TimeSpan.FromMinutes(timeoutMinutes));
```
