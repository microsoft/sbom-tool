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
using Ninject;
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
    public class SBOMGenerationWorkflow : IWorkflow
    {
        [Inject]
        public IFileSystemUtils FileSystemUtils { get; set; }

        [Inject]
        public IConfiguration Configuration { get; set; }

        [Inject]
        public ILogger Log { get; set; }

        [Inject]
        [Named(nameof(FileArrayGenerator))]
        public IJsonArrayGenerator FileArrayGenerator { get; set; }

        [Inject]
        [Named(nameof(PackageArrayGenerator))]
        public IJsonArrayGenerator PackageArrayGenerator { get; set; }

        [Inject]
        [Named(nameof(RelationshipsArrayGenerator))]
        public IJsonArrayGenerator RelationshipsArrayGenerator { get; set; }

        [Inject]
        [Named(nameof(ExternalDocumentReferenceGenerator))]
        public IJsonArrayGenerator ExternalDocumentReferenceGenerator { get; set; }

        [Inject]
        public ISbomConfigProvider SBOMConfigs { get; set; }

        [Inject]
        public IOSUtils OSUtils { get; set; }

        [Inject]
        public IRecorder Recorder { get; set; }

        public virtual async Task<bool> RunAsync()
        {
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

                    return !validErrors.Any();
                }
                catch (ManifestFolderExistsException e)
                {
                    Recorder.RecordException(e);
                    Log.Error("Encountered an error while generating the manifest.");
                    Log.Error($"Error details: {e.Message}");

                    return false;
                }
                catch (Exception e)
                {
                    Recorder.RecordException(e);
                    Log.Error("Encountered an error while generating the manifest.");
                    Log.Error($"Error details: {e.Message}");
                    deleteSBOMDir = true;

                    // TODO: Create EntityError with exception message and record to surface unexpected exceptions to client.
                    return false;
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

                    if (!deleteSbomDirSwitch)
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
