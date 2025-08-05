// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Reads SPDX json format SBOM file.
/// </summary>
public class SPDXSbomReaderForExternalDocumentReference : ISbomReaderForExternalDocumentReference
{
    private readonly ILogger log;
    private readonly IServiceProvider serviceProvider;

    public SPDXSbomReaderForExternalDocumentReference(ILogger log, IServiceProvider serviceProvider)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    }

    public virtual (ChannelReader<ExternalDocumentReferenceInfo> results, ChannelReader<FileValidationResult> errors) ParseSbomFile(ChannelReader<string> sbomFileLocation)
    {
        if (sbomFileLocation is null)
        {
            throw new ArgumentNullException(nameof(sbomFileLocation));
        }

        var output = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        Task.Run(async () =>
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var scopedFactory = scope.ServiceProvider.GetRequiredService<ISbomReferenceFactory>();
                IList<ExternalDocumentReferenceInfo> externalDocumentReferenceInfos = new List<ExternalDocumentReferenceInfo>();
                await foreach (var file in sbomFileLocation.ReadAllAsync())
                {
                    if (!file.EndsWith(Constants.SPDXFileExtension, StringComparison.OrdinalIgnoreCase))
                    {
                        log.Warning($"The file {file} is not an spdx document.");
                    }
                    else
                    {
                        try
                        {
                            var sbomRef = scopedFactory.GetSbomReferenceDescriber(file);
                            if (sbomRef is null)
                            {
                                log.Error($"The file {file} appears to be an SPDX file, but is not a recognized SPDX format.");
                                await errors.WriteResult(file);
                            }
                            else
                            {
                                var externalDocumentReference = sbomRef?.CreateExternalDocumentRefererence(file);
                                if (externalDocumentReference != null)
                                {
                                    externalDocumentReferenceInfos.Add(externalDocumentReference);
                                }
                            }
                        }
                        catch (JsonException e)
                        {
                            log.Error($"Encountered an error while parsing the external SBOM file {file}: {e.Message}");
                            await errors.WriteResult(file);
                        }
                        catch (HashGenerationException e)
                        {
                            log.Warning($"Encountered an error while generating hash for file {file}: {e.Message}");
                            await errors.WriteResult(file);
                        }
                        catch (Exception e)
                        {
                            log.Warning($"Encountered an error while generating externalDocumentReferenceInfo from file {file}: {e.Message}");
                            await errors.WriteResult(file);
                        }
                    }
                }

                foreach (var externalDocumentRefrence in externalDocumentReferenceInfos)
                {
                    await output.Writer.WriteAsync(externalDocumentRefrence);
                }
            }
            output.Writer.Complete();
            errors.Writer.Complete();
        });

        return (output, errors);
    }
}
