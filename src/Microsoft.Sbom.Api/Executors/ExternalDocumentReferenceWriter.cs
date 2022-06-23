// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Uses the <see cref="IManifestGenerator"/> to write a json object that contains 
    /// a format specific representation of the <see cref="ExternalDocumentReferenceInfo"/>.
    /// </summary>
    public class ExternalDocumentReferenceWriter
    {
        private readonly ManifestGeneratorProvider manifestGeneratorProvider;
        private readonly ILogger log;

        public ExternalDocumentReferenceWriter(
            ManifestGeneratorProvider manifestGeneratorProvider,
            ILogger log)
        {
            this.manifestGeneratorProvider = manifestGeneratorProvider ?? throw new ArgumentNullException(nameof(manifestGeneratorProvider));
            this.log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public (ChannelReader<JsonDocWithSerializer> result, ChannelReader<FileValidationResult> errors) Write(ChannelReader<ExternalDocumentReferenceInfo> externalDocumentReferenceInfos, IList<ISbomConfig> externalDocumentReferenceArraySupportingConfigs)
        {
            var errors = Channel.CreateUnbounded<FileValidationResult>();
            var result = Channel.CreateUnbounded<JsonDocWithSerializer>();

            if (externalDocumentReferenceInfos is null)
            {
                throw new ArgumentNullException(nameof(externalDocumentReferenceInfos));
            }

            if (externalDocumentReferenceArraySupportingConfigs is null)
            {
                throw new ArgumentNullException(nameof(externalDocumentReferenceArraySupportingConfigs));
            }

            Task.Run(async () =>
            {
                await foreach (ExternalDocumentReferenceInfo externalDocumentReferenceInfo in externalDocumentReferenceInfos.ReadAllAsync())
                {
                    foreach (var config in externalDocumentReferenceArraySupportingConfigs)
                    {
                        try
                        {
                            var generationResult = manifestGeneratorProvider
                                                   .Get(config.ManifestInfo)
                                                   .GenerateJsonDocument(externalDocumentReferenceInfo);
                            config.Recorder.RecordExternalDocumentReferenceIdAndRootElement(generationResult?.ResultMetadata?.EntityId, externalDocumentReferenceInfo.DescribedElementID);
                            await result.Writer.WriteAsync((generationResult?.Document, config.JsonSerializer));
                        }
                        catch (Exception e)
                        {
                            log.Warning($"Encountered an error while generating json for external document reference {externalDocumentReferenceInfo.ExternalDocumentName}: {e.Message}");
                            await errors.Writer.WriteAsync(new FileValidationResult
                            {
                                ErrorType = ErrorType.JsonSerializationError,
                                Path = externalDocumentReferenceInfo.ExternalDocumentName
                            });
                        }
                    }
                }

                errors.Writer.Complete();
                result.Writer.Complete();
            });

            return (result, errors);
        }
    }
}
