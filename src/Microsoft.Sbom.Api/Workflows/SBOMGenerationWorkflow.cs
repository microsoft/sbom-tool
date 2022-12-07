// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing.Algorithms;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Ninject;
using PowerArgs;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Workflows
{
    /// <summary>
    /// The SBOM tool workflow class that is used to generate a SBOM
    /// file for a given build root path.
    /// </summary>
    public class SBOMGenerationWorkflow : IWorkflow
    {
        private readonly ValidationResultGenerator validationResultGenerator;

        public IFileSystemUtils FileSystemUtils { get; }

        public IConfiguration Configuration { get; }

        public ILogger Log { get; }

        public IJsonArrayGenerator FileArrayGenerator { get; }
        
        public IJsonArrayGenerator PackageArrayGenerator { get; }
        
        public IJsonArrayGenerator RelationshipsArrayGenerator { get; }

        public IJsonArrayGenerator ExternalDocumentReferenceGenerator { get; }

        public ISbomConfigProvider SBOMConfigs { get; }

        public IOSUtils OSUtils { get; }

        public IRecorder Recorder { get; }

        public SBOMGenerationWorkflow(
            IConfiguration configuration,
            IFileSystemUtils fileSystemUtils,
            ILogger log,
            [Named(nameof(FileArrayGenerator))] IJsonArrayGenerator fileArrayGenerator,
            [Named(nameof(PackageArrayGenerator))] IJsonArrayGenerator packageArrayGenerator,
            [Named(nameof(RelationshipsArrayGenerator))] IJsonArrayGenerator relationshipsArrayGenerator,
            [Named(nameof(ExternalDocumentReferenceGenerator))] IJsonArrayGenerator externalDocumentReferenceGenerator,
            ISbomConfigProvider sbomConfigs,
            IOSUtils osUtils,
            IRecorder recorder,
            ValidationResultGenerator validationResultGenerator)
        {
            FileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            Log = log ?? throw new ArgumentNullException(nameof(log));
            FileArrayGenerator = fileArrayGenerator ?? throw new ArgumentNullException(nameof(fileArrayGenerator));
            PackageArrayGenerator = packageArrayGenerator ?? throw new ArgumentNullException(nameof(packageArrayGenerator));
            RelationshipsArrayGenerator = relationshipsArrayGenerator ?? throw new ArgumentNullException(nameof(relationshipsArrayGenerator));
            ExternalDocumentReferenceGenerator = externalDocumentReferenceGenerator ?? throw new ArgumentNullException(nameof(externalDocumentReferenceGenerator));
            SBOMConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
            OSUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));
            Recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
            this.validationResultGenerator = validationResultGenerator ?? throw new ArgumentNullException(nameof(validationResultGenerator));
        }

        public virtual async Task<ValidationResult> RunAsync()
        {
            var sw = Stopwatch.StartNew();
            IList<FileValidationResult> validErrors = new List<FileValidationResult>();
            string sbomDir = null;
            bool deleteSBOMDir = false;
            using (Recorder.TraceEvent(Events.SBOMGenerationWorkflow))
            {
                try
                {
                    Log.Debug("Starting SBOM generation workflow.");

                    sbomDir = Configuration.ManifestDirPath.Value;

                    // Don't remove directory if path is provided by user, there could be other files in that directory
                    if (Configuration.ManifestDirPath.IsDefaultSource)
                    {
                        RemoveExistingManifestDirectory();
                    }

                    await using (SBOMConfigs.StartJsonSerializationAsync())
                    {
                        SBOMConfigs.ApplyToEachConfig(config => config.JsonSerializer.StartJsonObject());

                        // Files section
                        validErrors = await FileArrayGenerator.GenerateAsync();

                        // Packages section
                        validErrors.Concat(await PackageArrayGenerator.GenerateAsync());

                        // External Document Reference section
                        validErrors.Concat(await ExternalDocumentReferenceGenerator.GenerateAsync());

                        // Relationships section
                        validErrors.Concat(await RelationshipsArrayGenerator.GenerateAsync());

                        // Write headers
                        SBOMConfigs.ApplyToEachConfig(config =>
                            config.JsonSerializer.WriteJsonString(
                                config.MetadataBuilder.GetHeaderJsonString(SBOMConfigs)));

                        // Finalize JSON
                        SBOMConfigs.ApplyToEachConfig(config => config.JsonSerializer.FinalizeJsonObject());
                    }

                    // Generate SHA256 for manifest json
                    SBOMConfigs.ApplyToEachConfig(config => GenerateHashForManifestJson(config.ManifestJsonFilePath));

                    return validationResultGenerator
                                            .WithValidationResults(validErrors.ToArray())
                                            .WithTotalDuration(sw.Elapsed)
                                            .Build(generateValidationTelemetry: false);
                }
                catch (Exception e)
                {
                    Recorder.RecordException(e);
                    Log.Error("Encountered an error while generating the manifest.");
                    Log.Error($"Error details: {e.Message}");

                    if (!(e is ManifestFolderExistsException))
                    {
                        deleteSBOMDir = true;
                    }

                    // TODO: Create EntityError with exception message and record to surface unexpected exceptions to client.
                    return validationResultGenerator.FailureResult;
                }
                finally
                {
                    if (validErrors != null)
                    {
                        Recorder.RecordTotalErrors(validErrors);
                    }

                    // Delete the generated _manifest folder if generation failed.
                    if (deleteSBOMDir || validErrors.Any())
                    {
                        DeleteManifestFolder(sbomDir);
                    }
                }
            }
        }
        
        private void DeleteManifestFolder(string sbomDir)
        {
            try
            {
                if (!string.IsNullOrEmpty(sbomDir) && FileSystemUtils.DirectoryExists(sbomDir))
                {
                    if (Configuration.ManifestDirPath.IsDefaultSource)
                    {
                        FileSystemUtils.DeleteDir(sbomDir, true);
                    }
                    else if (!FileSystemUtils.IsDirectoryEmpty(sbomDir))
                    {
                        Log.Warning($"Manifest generation failed, however we were " +
                                    $"unable to delete the partially generated manifest.json file and the {sbomDir} directory because the directory was not empty.");
                    }
                }
            }
            catch (Exception e)
            {
                Log.Warning(
                    $"Manifest generation failed, however we were " +
                    $"unable to delete the partially generated manifest.json file and the {sbomDir} directory.", e);
            }
        }

        private void GenerateHashForManifestJson(string manifestJsonFilePath)
        {
            if (!FileSystemUtils.FileExists(manifestJsonFilePath))
            {
                Log.Warning($"Failed to create manifest hash because the manifest json file does not exist.");
                return;
            }

            string hashFileName = $"{manifestJsonFilePath}.sha256";

            using var readStream = FileSystemUtils.OpenRead(manifestJsonFilePath);
            using var bufferedStream = new BufferedStream(readStream, 1024 * 32);
            using var writeFileStream = FileSystemUtils.OpenWrite(hashFileName);
            var hashValue = Encoding.Unicode.GetBytes(BitConverter.ToString(new Sha256HashAlgorithm().ComputeHash(bufferedStream)).Replace("-", string.Empty).ToLower());
            writeFileStream.Write(hashValue, 0, hashValue.Length);
        }

        private void RemoveExistingManifestDirectory()
        {
            var rootManifestFolderPath = Configuration.ManifestDirPath.Value;

            try
            {
                // If the _manifest directory already exists, we must delete it first to avoid having 
                // multiple SBOMs for the same drop. However, the default behaviour is to fail with an
                // Exception since we don't want to inadvertently delete someone else's data. This behaviour
                // can be overridden by setting an environment variable.
                if (FileSystemUtils.DirectoryExists(rootManifestFolderPath))
                {
                    bool.TryParse(
                        OSUtils.GetEnvironmentVariable(Constants.DeleteManifestDirBoolVariableName),
                        out bool deleteSbomDirSwitch);

                    Recorder.RecordSwitch(Constants.DeleteManifestDirBoolVariableName, deleteSbomDirSwitch);

                    if (!deleteSbomDirSwitch && !(Configuration.DeleteManifestDirIfPresent?.Value ?? false))
                    {
                        throw new ManifestFolderExistsException(
                            $"The BuildDropRoot folder already contains a _manifest folder. Please" +
                            $" delete this folder before running the generation or set the " +
                            $"{Constants.DeleteManifestDirBoolVariableName} environment variable to 'true' to " +
                            $"overwrite this folder.");
                    }

                    Log.Warning(
                        $"Deleting pre-existing folder {rootManifestFolderPath} as {Constants.DeleteManifestDirBoolVariableName}" +
                        $" is 'true'.");
                    FileSystemUtils.DeleteDir(rootManifestFolderPath, true);
                }
            }
            catch (ManifestFolderExistsException)
            {
                // Rethrow exception if manifest folder already exists.
                throw;
            }
            catch (Exception e)
            {
                throw new ValidationArgException(
                    $"Unable to create manifest directory at path {rootManifestFolderPath}. Error: {e.Message}");
            }
        }
    }
}
