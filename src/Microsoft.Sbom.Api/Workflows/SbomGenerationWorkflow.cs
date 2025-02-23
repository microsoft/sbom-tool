// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
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
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Workflows;

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
        var deleteSbomDir = false;
        using (recorder.TraceEvent(Events.SbomGenerationWorkflow))
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
                else
                {
                    log.Information("Manifest directory path was explicitly defined. Will not attempt to delete any existing _manifest directory.");
                }

                var manifestInfos = configuration.ManifestInfo.Value;

                // Use the WriteJsonObjectsToSbomAsync method based on the SPDX version in manifest info
                foreach (var manifestInfo in manifestInfos)
                {
                    var config = sbomConfigs.Get(manifestInfo);
                    await using (sbomConfigs.StartJsonSerializationAsync(config))
                    {
                        config.JsonSerializer?.StartJsonObject();

                        // Get the appropriate strategy
                        var serializationStrategy = JsonSerializationStrategyFactory.GetStrategy(manifestInfo.Version);
                        validErrors = await serializationStrategy.WriteJsonObjectsToSbomAsync(
                            config,
                            manifestInfo.Version,
                            fileArrayGenerator,
                            packageArrayGenerator,
                            relationshipsArrayGenerator,
                            externalDocumentReferenceGenerator).
                            ConfigureAwait(false);

                        // Write headers
                        serializationStrategy.AddHeadersToSbom(sbomConfigs, config);

                        // Finalize JSON
                        config.JsonSerializer?.FinalizeJsonObject();
                    }

                    // Generate SHA256 for manifest json
                    GenerateHashForManifestJson(config.ManifestJsonFilePath);
                }

                return !validErrors.Any();
            }
            catch (Exception e)
            {
                recorder.RecordException(e);
                log.Error("Encountered an error while generating the manifest.");
                log.Error($"Error details: {e.Message}");

                if (e is not ManifestFolderExistsException)
                {
                    deleteSbomDir = true;
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
                if (deleteSbomDir || validErrors.Any())
                {
                    DeleteManifestFolder(sbomDir);
                }

                try
                {
                    // Delete the generated temp folder if necessary
                    if (fileSystemUtils.DirectoryExists(fileSystemUtils.GetSbomToolTempPath()))
                    {
                        fileSystemUtils.DeleteDir(fileSystemUtils.GetSbomToolTempPath(), true);
                    }
                }
                catch (Exception e)
                {
                    log.Warning($"Unable to delete the temp directory {fileSystemUtils.GetSbomToolTempPath()}", e);
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
            this.log.Warning(
                $"Manifest generation failed, however we were " +
                $"unable to delete the partially generated manifest.json file and the {sbomDir} directory.",
                e);
        }
    }

    private void GenerateHashForManifestJson(string manifestJsonFilePath)
    {
        if (!fileSystemUtils.FileExists(manifestJsonFilePath))
        {
            log.Warning($"Failed to create manifest hash because the manifest json file does not exist.");
            return;
        }

        var hashFileName = $"{manifestJsonFilePath}.sha256";

        using var readStream = fileSystemUtils.OpenRead(manifestJsonFilePath);
        using var bufferedStream = new BufferedStream(readStream, 1024 * 32);
        var hashBytes = new Sha256HashAlgorithm().ComputeHash(bufferedStream);
        var hashValue = Convert.ToHexString(hashBytes).ToLowerInvariant();
        fileSystemUtils.WriteAllText(hashFileName, hashValue);
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
                    out var deleteSbomDirSwitch);

                recorder.RecordSwitch(Constants.DeleteManifestDirBoolVariableName, deleteSbomDirSwitch);

                if (!deleteSbomDirSwitch && !(configuration.DeleteManifestDirIfPresent?.Value ?? false))
                {
                    throw new ManifestFolderExistsException(
                        $"The BuildDropRoot folder already contains a _manifest folder. Please" +
                        $" delete this folder before running the generation or set the " +
                        $"{Constants.DeleteManifestDirBoolVariableName} environment variable to 'true' to " +
                        $"overwrite this folder.");
                }

                log.Information(
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
