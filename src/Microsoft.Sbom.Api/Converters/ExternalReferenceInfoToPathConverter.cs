// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Converters;

/// <summary>
/// Converts ExternalDocumentReferenceInfo objects to their path as string.
/// </summary>
public class ExternalReferenceInfoToPathConverter
{
    private readonly ILogger<ExternalReferenceInfoToPathConverter> log;

    public ExternalReferenceInfoToPathConverter(ILogger<ExternalReferenceInfoToPathConverter> log)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public (ChannelReader<string> output, ChannelReader<FileValidationResult> errors) Convert(ChannelReader<ExternalDocumentReferenceInfo> externalDocumentRefReader)
    {
        var output = Channel.CreateUnbounded<string>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        Task.Run(async () =>
        {
            await foreach (var externalDocumentRef in externalDocumentRefReader.ReadAllAsync())
            {
                try
                {
                    var path = externalDocumentRef.Path;

                    if (path == null)
                    {
                        log.LogDebug($"Encountered an error while converting external reference {externalDocumentRef.ExternalDocumentName} for null path.");
                        await errors.Writer.WriteAsync(new FileValidationResult
                        {
                            ErrorType = ErrorType.Other,

                            // on the exception that Path does not exist, use DocumentName for uniqueness
                            Path = externalDocumentRef.ExternalDocumentName
                        });
                    }
                    else
                    {
                        await output.Writer.WriteAsync(path);
                    }
                }
                catch (Exception e)
                {
                    log.LogDebug($"Encountered an error while converting external reference {externalDocumentRef.ExternalDocumentName} to path: {e.Message}");
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = ErrorType.Other,
                        Path = externalDocumentRef.Path
                    });
                }
            }

            output.Writer.Complete();
            errors.Writer.Complete();
        });

        return (output, errors);
    }
}
