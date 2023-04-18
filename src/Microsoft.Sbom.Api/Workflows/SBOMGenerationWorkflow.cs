// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing.Algorithms;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using PowerArgs;
using Serilog;
using System;
using System.Collections.Generic;
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
    public class SbomGenerationWorkflow : IWorkflow<SbomGenerationWorkflow>
    {
        private readonly IFileSystemUtils fileSystemUtils;

        private readonly IConfiguration configuration;

        private readonly ILogger log;

        private readonly IJsonArrayGenerator<FileArrayGenerator> fileArrayGenerator;

        private readonly IJsonArrayGenerator<PackageArrayGenerator> packageArrayGenerator;

        private readonly IJsonArrayGenerator<RelationshipsArrayGenerator> relationshipsArrayGenerator;

        private readonly IJsonArrayGenerator<ExternalDocumentReferenceGenerator> externalDocumentReferenceGenerator;

        private readonly ISbomConfigProvider sbomConfigs;

        private readonly IOSUtils osUtils;

        private readonly IRecorder recorder;

        public SbomGenerationWorkflow(
            IConfiguration configuration,
            IFileSystemUtils fileSystemUtils,
            ILogger log,
            IJsonArrayGenerator<FileArrayGenerator> fileArrayGenerator,
            IJsonArrayGenerator<PackageArrayGenerator> packageArrayGenerator,
            IJsonArrayGenerator<RelationshipsArrayGenerator> relationshipsArrayGenerator,
            IJsonArrayGenerator<ExternalDocumentReferenceGenerator> externalDocumentReferenceGenerator,
            ISbomConfigProvider sbomConfigs,
            IOSUtils osUtils,
            IRecorder recorder)
        {
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.log = log ?? throw new ArgumentNullException(nameof(log));
            this.fileArrayGenerator = fileArrayGenerator ?? throw new ArgumentNullException(nameof(fileArrayGenerator));
            this.packageArrayGenerator = packageArrayGenerator ?? throw new ArgumentNullException(nameof(packageArrayGenerator));
            this.relationshipsArrayGenerator = relationshipsArrayGenerator ?? throw new ArgumentNullException(nameof(relationshipsArrayGenerator));
            this.externalDocumentReferenceGenerator = externalDocumentReferenceGenerator ?? throw new ArgumentNullException(nameof(externalDocumentReferenceGenerator));
            this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
            this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));
            this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        }

        public virtual async Task<bool> RunAsync()
        {
            IList<FileValidationResult> validErrors = new List<FileValidationResult>();
            string sbomDir = null;
            bool deleteSBOMDir = false;
            using (recorder.TraceEvent(Events.SBOMGenerationWorkflow))
            {
                try
                {
                    log.Debug("Starting SBOM generation workflow.");

                    sbomDir = configuration.ManifestDirPath.Value;

                    // Don't remove directory if path is provided by user, there could be other files in that directory
                    if (configuration.ManifestDirPath.IsDefaultSource)
                    {
                        RemoveExistingManifestDirectory();
                    }

                    await using (sbomConfigs.StartJsonSerializationAsync())
                    {
                        sbomConfigs.ApplyToEachConfig(config => config.JsonSerializer.StartJsonObject());

                        // Files section
                        validErrors = await fileArrayGenerator.GenerateAsync();

                        // Packages section
                        validErrors.Concat(await packageArrayGenerator.GenerateAsync());

                        // External Document Reference section
                        validErrors.Concat(await externalDocumentReferenceGenerator.GenerateAsync());

                        // Relationships section
                        validErrors.Concat(await relationshipsArrayGenerator.GenerateAsync());

                        // Write headers
                        sbomConfigs.ApplyToEachConfig(config =>
                            config.JsonSerializer.WriteJsonString(
                                config.MetadataBuilder.GetHeaderJsonString(sbomConfigs)));

                        // Finalize JSON
                        sbomConfigs.ApplyToEachConfig(config => config.JsonSerializer.FinalizeJsonObject());
                    }

                    // Generate SHA256 for manifest json
                    sbomConfigs.ApplyToEachConfig(config => GenerateHashForManifestJson(config.ManifestJsonFilePath));

                    return !validErrors.Any();
                }
                catch (Exception e)
                {
                    recorder.RecordException(e);
                    log.Error("Encountered an error while generating the manifest.");
                    log.Error($"Error details: {e.Message}");

                    if (e is not ManifestFolderExistsException)
                    {
                        deleteSBOMDir = true;
                    }

                    // TODO: Create EntityError with exception message and record to surface unexpected exceptions to client.
                    return false;
                }
                finally
                {
                    if (validErrors != null)
                    {
                        recorder.RecordTotalErrors(validErrors);
                    }

                    // Delete the generated _manifest folder if generation failed.
                    if (deleteSBOMDir || validErrors.Any())
                    {
                        DeleteManifestFolder(sbomDir);
                    }

                    try
                    {
                        // Delete the generated temp folder if necessary 
                        if (fileSystemUtils.DirectoryExists(IFileSystemUtils.RandomTempPath))
                        {
                            fileSystemUtils.DeleteDir(IFileSystemUtils.RandomTempPath, true);
                        }
                    }
                    catch (Exception e)
                    {
                        log.Warning($"Unable to delete the temp directory {IFileSystemUtils.RandomTempPath}", e);
                    }          
                }
            }
        }
        
        private void DeleteManifestFolder(string sbomDir)
        {
            try
            {
                if (!string.IsNullOrEmpty(sbomDir) && fileSystemUtils.DirectoryExists(sbomDir))
                {
                    if (configuration.ManifestDirPath.IsDefaultSource)
                    {
                        fileSystemUtils.DeleteDir(sbomDir, true);
                    }
                    else if (!fileSystemUtils.IsDirectoryEmpty(sbomDir))
                    {
                        log.Warning($"Manifest generation failed, however we were " +
                                    $"unable to delete the partially generated manifest.json file and the {sbomDir} directory because the directory was not empty.");
                    }
                }
            }
            catch (Exception e)
            {
                log.Warning(
                    $"Manifest generation failed, however we were " +
                    $"unable to delete the partially generated manifest.json file and the {sbomDir} directory.", e);
            }
        }

        private void GenerateHashForManifestJson(string manifestJsonFilePath)
        {
            if (!fileSystemUtils.FileExists(manifestJsonFilePath))
            {
                log.Warning($"Failed to create manifest hash because the manifest json file does not exist.");
                return;
            }

            string hashFileName = $"{manifestJsonFilePath}.sha256";

            using var readStream = fileSystemUtils.OpenRead(manifestJsonFilePath);
            using var bufferedStream = new BufferedStream(readStream, 1024 * 32);
            using var writeFileStream = fileSystemUtils.OpenWrite(hashFileName);
            var hashValue = Encoding.Unicode.GetBytes(BitConverter.ToString(new Sha256HashAlgorithm().ComputeHash(bufferedStream)).Replace("-", string.Empty).ToLower());
            writeFileStream.Write(hashValue, 0, hashValue.Length);
        }

        private void RemoveExistingManifestDirectory()
        {
            var rootManifestFolderPath = configuration.ManifestDirPath.Value;

            try
            {
                // If the _manifest directory already exists, we must delete it first to avoid having 
                // multiple SBOMs for the same drop. However, the default behaviour is to fail with an
                // Exception since we don't want to inadvertently delete someone else's data. This behaviour
                // can be overridden by setting an environment variable.
                if (fileSystemUtils.DirectoryExists(rootManifestFolderPath))
                {
                    bool.TryParse(
                        osUtils.GetEnvironmentVariable(Constants.DeleteManifestDirBoolVariableName),
                        out bool deleteSbomDirSwitch);

                    recorder.RecordSwitch(Constants.DeleteManifestDirBoolVariableName, deleteSbomDirSwitch);

                    if (!deleteSbomDirSwitch && !(configuration.DeleteManifestDirIfPresent?.Value ?? false))
                    {
                        throw new ManifestFolderExistsException(
                            $"The BuildDropRoot folder already contains a _manifest folder. Please" +
                            $" delete this folder before running the generation or set the " +
                            $"{Constants.DeleteManifestDirBoolVariableName} environment variable to 'true' to " +
                            $"overwrite this folder.");
                    }

                    log.Warning(
                        $"Deleting pre-existing folder {rootManifestFolderPath} as {Constants.DeleteManifestDirBoolVariableName}" +
                        $" is 'true'.");
                    fileSystemUtils.DeleteDir(rootManifestFolderPath, true);
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
