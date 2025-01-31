// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Identity.Services.Crypto;
using Microsoft.Identity.Services.DataProtection;
using Microsoft.Identity.Services.DataProtection.Jwt.Signing;
using Microsoft.Identity.Services.DataProtection.Secrets;
using Microsoft.Identity.Services.DataProtection.Serialization.Json;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing.Algorithms;
using Microsoft.Sbom.Api.Manifest.ManifestConfigHandlers;
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
        var deleteSBOMDir = false;
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
                else
                {
                    log.Information("Manifest directory path was explicitly defined. Will not attempt to delete any existing _manifest directory.");
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

                // Maria: for this demo assume that only one spdx file was created.
                // Compute its path and sign it using my personal MSFT certificate // later change it to AME and run on the saw and debug the exe
                Console.ForegroundColor = ConsoleColor.Cyan;

                var sbomRelativeFilePath = Path.Combine(sbomDir, "spdx_2.2", "manifest.spdx.json");
                if (File.Exists(sbomRelativeFilePath))
                {
                    Console.WriteLine($"DPP Signing the SPDX file at {sbomRelativeFilePath}");
                    SignWithDPP(sbomRelativeFilePath);
                }
                else
                {
                    Console.WriteLine($"SPDX file path does not exist = {sbomRelativeFilePath}");
                }

                Console.ForegroundColor = ConsoleColor.White;

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

    private void SignWithDPP(string spdxFilePath)
    {
        var logHeader = $"{nameof(SignWithDPP)}";
        Console.WriteLine($"{logHeader} - retrieving current user's corp certificate");
        var signingCert = GetUserCertificate();

        if (signingCert == null)
        {
            Console.WriteLine($"{logHeader} - no corp certificate found. Cannot sign spdx file.");
            return;
        }

        // make the additional context
        var context = new Dictionary<string, string>
        {
            { "PlaceholderKey", "test" },
        }.ToDataContext();

        // create the cert source and cert validator
        var signingCertificate = CachedCertificate.Create(signingCert);
        var validator = new MyCertValidator();
        ISecretSerializer<ICachedCertificate> secretSerializer = new PublicCertificateSerializer();
        var certSource = CachedCertificateSource.CreateSelfManagedSource(secretSerializer, validator, signingCertificate);

        // create the content serializer
        var jsonSerializer = new JsonContentSerializer(preserveOrder: true);
        var signatureConfiguration = new JsonSignatureConfiguration(
            version: 1,
            keySource: certSource.AsReadOnlyAsymmetricKeySource(),
            serializer: jsonSerializer);

        // create the signature boundary container
        ISignatureBoundaryContainer signatureBoundaryContainer = new SignatureBoundaryContainer(signatureConfiguration);

        // sign the file
        var fileContentBytes = File.ReadAllBytes(spdxFilePath);
        Console.WriteLine($"{logHeader} - signing sbom file {spdxFilePath}");
        var signature = signatureBoundaryContainer.SignDataAsString(
            fileContentBytes,
            context);

        // write signature in separate file
        var signatureFile = Path.Combine(Path.GetDirectoryName(spdxFilePath), $"manifest.spdx.json.signature.txt");
        File.WriteAllText(signatureFile, signature);
        Console.WriteLine($"Wrote signature to file {signatureFile}");
    }

    /// <summary>
    /// custom certificate validator for DPP
    /// </summary>
    private class MyCertValidator : ISecretValidator<ICachedCertificate>
    {
        public bool Validate(ICachedCertificate secret)
        {
            // TODO: Public cert validation logic goes here when it will be available.
            return true;
        }
    }

    private X509Certificate2 GetUserCertificate()
    {
        var logHeader = $"{nameof(GetUserCertificate)}";
        using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadOnly);
            var certs = store.Certificates;
            X509Certificate2 signingCert = null;
            foreach (var cert in certs)
            {
                if (cert.Subject.Contains("DC=corp"))
                {
                    signingCert = cert;
                    break;
                }
            }

            if (signingCert == null)
            {
                Console.WriteLine($"{logHeader} - no corp certificate found. Cannot sign spdx file.");
                return null;
            }

            Console.WriteLine($"{logHeader} - found corp certificate");
            Console.WriteLine("Subject: " + signingCert.Subject);
            Console.WriteLine("Issuer" + signingCert.Issuer);

            if (!signingCert.HasPrivateKey)
            {
                Console.WriteLine($"{logHeader} - certificate does not have private key. Cannot sign spdx file.");
                return null;
            }

            Console.WriteLine($"{logHeader} - certificate has private key.");

            return signingCert;
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
