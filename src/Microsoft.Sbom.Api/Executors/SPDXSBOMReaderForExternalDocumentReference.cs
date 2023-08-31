// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;
using Constants = Microsoft.Sbom.Api.Utils.Constants;
using ErrorType = Microsoft.Sbom.Api.Entities.ErrorType;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Reads SPDX json format SBOM file.
/// </summary>
public class SPDXSBOMReaderForExternalDocumentReference : ISBOMReaderForExternalDocumentReference
{
    private readonly IHashCodeGenerator hashCodeGenerator;
    private readonly ILogger log;
    private readonly ISbomConfigProvider sbomConfigs;
    private readonly ManifestGeneratorProvider manifestGeneratorProvider;
    private AlgorithmName[] hashAlgorithmNames;
    private readonly IFileSystemUtils fileSystemUtils;

    private readonly IEnumerable<string> supportedSPDXVersions = new List<string> { "SPDX-2.2" };

    private AlgorithmName[] HashAlgorithmNames
    {
        get
        {
            hashAlgorithmNames ??= sbomConfigs.GetManifestInfos()
                .Select(config => manifestGeneratorProvider
                    .Get(config)
                    .RequiredHashAlgorithms)
                .SelectMany(h => h)
                .Distinct()
                .ToArray();

            return hashAlgorithmNames;
        }
    }

    public SPDXSBOMReaderForExternalDocumentReference(
        IHashCodeGenerator hashCodeGenerator,
        ILogger log,
        ISbomConfigProvider sbomConfigs,
        ManifestGeneratorProvider manifestGeneratorProvider,
        IFileSystemUtils fileSystemUtils)
    {
        this.hashCodeGenerator = hashCodeGenerator ?? throw new ArgumentNullException(nameof(hashCodeGenerator));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
        this.manifestGeneratorProvider = manifestGeneratorProvider ?? throw new ArgumentNullException(nameof(manifestGeneratorProvider));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    public virtual (ChannelReader<ExternalDocumentReferenceInfo> results, ChannelReader<FileValidationResult> errors) ParseSBOMFile(ChannelReader<string> sbomFileLocation)
    {
        if (sbomFileLocation is null)
        {
            throw new ArgumentNullException(nameof(sbomFileLocation));
        }

        var output = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        Task.Run(async () =>
        {
            IList<ExternalDocumentReferenceInfo> externalDocumentReferenceInfos = new List<ExternalDocumentReferenceInfo>();
            await foreach (string file in sbomFileLocation.ReadAllAsync())
            {
                if (!file.EndsWith(Constants.SPDXFileExtension, StringComparison.OrdinalIgnoreCase))
                {
                    log.Warning($"The file {file} is not an spdx document.");
                }
                else
                {
                    try
                    {
                        var externalDocumentReference = ReadJson(file);
                        if (externalDocumentReference != null)
                        {
                            externalDocumentReferenceInfos.Add(externalDocumentReference);
                        }
                    }
                    catch (JsonException e)
                    {
                        log.Error($"Encountered an error while parsing the external SBOM file {file}: {e.Message}");
                        await errors.Writer.WriteAsync(new FileValidationResult
                        {
                            ErrorType = ErrorType.Other,
                            Path = file
                        });
                    }
                    catch (HashGenerationException e)
                    {
                        log.Debug($"Encountered an error while generating hash for file {file}: {e.Message}");
                        await errors.Writer.WriteAsync(new FileValidationResult
                        {
                            ErrorType = ErrorType.Other,
                            Path = file
                        });
                    }
                    catch (Exception e)
                    {
                        log.Debug($"Encountered an error while generating externalDocumentReferenceInfo from file {file}: {e.Message}");
                        await errors.Writer.WriteAsync(new FileValidationResult
                        {
                            ErrorType = ErrorType.Other,
                            Path = file
                        });
                    }
                }
            }

            foreach (var externalDocumentRefrence in externalDocumentReferenceInfos)
            {
                await output.Writer.WriteAsync(externalDocumentRefrence);
            }

            output.Writer.Complete();
            errors.Writer.Complete();
        });

        return (output, errors);
    }

    private ExternalDocumentReferenceInfo ReadJson(string file)
    {
        Checksum[] checksums;
        checksums = hashCodeGenerator.GenerateHashes(file, HashAlgorithmNames);

        using (var openStream = fileSystemUtils.OpenRead(file))
        using (JsonDocument doc = JsonDocument.Parse(openStream))
        {
            JsonElement root = doc.RootElement;
            string nameValue;
            string documentNamespaceValue;
            string versionValue;
            string rootElementValue;

            if (root.TryGetProperty(Constants.SpdxVersionString, out JsonElement version))
            {
                versionValue = version.GetString();
            }
            else
            {
                throw new Exception($"{Constants.SpdxVersionString} property could not be parsed from referenced SPDX Document '{file}', this is not a valid SPDX-2.2 Document.");
            }

            if (!IsSPDXVersionSupported(versionValue))
            {
                throw new Exception($"The SPDX version ${versionValue} is not valid format in the referenced SBOM, we currently only support SPDX-2.2 SBOM format.");
            }

            if (root.TryGetProperty(Constants.NameString, out JsonElement name))
            {
                nameValue = name.GetString();
            }
            else
            {
                throw new Exception($"{Constants.NameString} property could not be parsed from referenced SPDX Document '{file}'.");
            }

            if (root.TryGetProperty(Constants.DocumentNamespaceString, out JsonElement documentNamespace))
            {
                documentNamespaceValue = documentNamespace.GetString();
            }
            else
            {
                throw new Exception($"{Constants.DocumentNamespaceString} property could not be parsed from referenced SPDX Document '{file}'.");
            }

            if (root.TryGetProperty(Constants.DocumentDescribesString, out JsonElement rootElements))
            {
                rootElementValue = rootElements.EnumerateArray().FirstOrDefault().ToString() ?? Constants.DefaultRootElement;
            }
            else
            {
                throw new Exception($"{Constants.DocumentDescribesString} property could not be parsed from referenced SPDX Document '{file}'.");
            }

            return new ExternalDocumentReferenceInfo
            {
                DocumentNamespace = documentNamespaceValue,
                ExternalDocumentName = nameValue,
                Checksum = checksums,
                DescribedElementID = rootElementValue
            };
        }
    }

    private bool IsSPDXVersionSupported(string version) => supportedSPDXVersions.Contains(version);
}