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
using Microsoft.Sbom.Extensions.Entities;
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
        IEnumerable<FileValidationResult> validErrors = new List<FileValidationResult>();
        var elementsSpdxIdList = new HashSet<string>();
        string sbomDir = null;
        var deleteSbomDir = false;
        var triedToGenerateAtLeastOneManifest = false;

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

                // Write manifests based on manifestInfo values in the configuration.
                var targetConfigs = GetTargetConfigs(configuration.ManifestInfo.Value);
                triedToGenerateAtLeastOneManifest = targetConfigs.Any();

                await using (sbomConfigs.StartJsonSerializationAsync(targetConfigs))
                {
                    ForEachConfig(targetConfigs, config => config.JsonSerializer.StartJsonObject());

                    ForEachConfig(targetConfigs, config =>
                    {
                        var strategy = JsonSerializationStrategyFactory.GetStrategy(config.ManifestInfo.Version);
                        strategy.StartGraphArray(config);
                    });

                    // Write all the JSON documents from the generationResults to the manifest based on the manifestInfo.
                    var fileGeneratorResult = await fileArrayGenerator.GenerateAsync(targetConfigs, elementsSpdxIdList);

                    var packageGeneratorResult = await packageArrayGenerator.GenerateAsync(targetConfigs, elementsSpdxIdList);

                    var externalDocumentReferenceGeneratorResult = await externalDocumentReferenceGenerator.GenerateAsync(targetConfigs, elementsSpdxIdList);

                    var relationshipGeneratorResult = await relationshipsArrayGenerator.GenerateAsync(targetConfigs, elementsSpdxIdList);

                    // Concatenate all the errors from the generationResults.
                    validErrors = validErrors.Concat(fileGeneratorResult.Errors);
                    validErrors = validErrors.Concat(packageGeneratorResult.Errors);
                    validErrors = validErrors.Concat(externalDocumentReferenceGeneratorResult.Errors);
                    validErrors = validErrors.Concat(relationshipGeneratorResult.Errors);

                    // Write metadata dictionary to SBOM. This is a no-op for SPDX 3.0 and above.
                    ForEachConfig(targetConfigs, config =>
                    {
                        var strategy = JsonSerializationStrategyFactory.GetStrategy(config.ManifestInfo.Version);
                        strategy.AddMetadataToSbom(sbomConfigs, config);
                    });

                    ForEachConfig(targetConfigs, config =>
                    {
                        var strategy = JsonSerializationStrategyFactory.GetStrategy(config.ManifestInfo.Version);
                        strategy.EndGraphArray(config);
                    });

                    // Finalize JSON
                    ForEachConfig(targetConfigs, config => config.JsonSerializer.FinalizeJsonObject());
                }

                // Generate SHA256 for manifest json
                ForEachConfig(targetConfigs, config => GenerateHashForManifestJson(config.ManifestJsonFilePath));

                return triedToGenerateAtLeastOneManifest && !validErrors.Any();
            }
            catch (Exception e)
            {
                recorder.RecordException(e);
                log.Error("Encountered an error while generating the manifest.");
                log.Error("Error details: {Message}", e.Message);

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
                    recorder.RecordTotalErrors(validErrors.ToList());
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
                    log.Warning("Unable to delete the temp directory {SbomToolTempPath}", this.fileSystemUtils.GetSbomToolTempPath(), e);
                }
            }
        }
    }

    private IEnumerable<ISbomConfig> GetTargetConfigs(IEnumerable<ManifestInfo> manifestInfosFromConfiguration)
    {
        var configs = new List<ISbomConfig>();
        foreach (var manifestInfo in manifestInfosFromConfiguration)
        {
            if (sbomConfigs.TryGet(manifestInfo, out var config))
            {
                configs.Add(config);
            }
            else
            {
                log.Warning("Ignoring unregistered manifest type: {ManifestInfo}", manifestInfo);
            }
        }

        return configs;
    }

    /// <summary>
    /// For each supported config in the configuration, execute the provided action.
    /// </summary>
    /// <param name="targetConfigs">List of supported configs.</param>
    /// <param name="action">Action to perform on each config.</param>
    private void ForEachConfig(IEnumerable<ISbomConfig> targetConfigs, Action<ISbomConfig> action)
    {
        foreach (var config in targetConfigs)
        {
            action(config);
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
                    log.Warning("Manifest generation failed, however we were unable to delete the partially generated manifest.json file and the {Dir} directory because the directory was not empty.", sbomDir);
                }
            }
        }
        catch (Exception e)
        {
            this.log.Warning("Manifest generation failed, however we were unable to delete the partially generated manifest.json file and the {Dir} directory.", sbomDir, e);
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

                log.Warning(
                    "Deleting pre-existing folder {Path} as {Name} is 'true'.", rootManifestFolderPath, Constants.DeleteManifestDirBoolVariableName);
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
