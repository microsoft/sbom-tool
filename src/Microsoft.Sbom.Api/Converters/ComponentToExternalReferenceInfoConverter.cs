// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Converters;

/// <summary>
/// Converts ScannedComponent objects of SbomComponent type to ExternalDocumentReferenceInfo.
/// </summary>
public class ComponentToExternalReferenceInfoConverter
{
    private readonly ILogger<ComponentToExternalReferenceInfoConverter> log;

    public ComponentToExternalReferenceInfoConverter(ILogger<ComponentToExternalReferenceInfoConverter> log)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public (ChannelReader<ExternalDocumentReferenceInfo> output, ChannelReader<FileValidationResult> errors) Convert(ChannelReader<ScannedComponent> componentReader)
    {
        var output = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        Task.Run(async () =>
        {
            await foreach (var scannedComponent in componentReader.ReadAllAsync())
            {
                try
                {
                    var document = ConvertComponentToExternalReference(scannedComponent);
                    await output.Writer.WriteAsync(document);
                }
                catch (Exception e)
                {
                    log.LogDebug($"Encountered an error while converting SBOM component {scannedComponent.Component.Id} to external reference: {e.Message}");
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = Entities.ErrorType.PackageError,
                        Path = scannedComponent.LocationsFoundAt?.FirstOrDefault()
                    });
                }
            }

            output.Writer.Complete();
            errors.Writer.Complete();
        });

        return (output, errors);
    }

    private ExternalDocumentReferenceInfo ConvertComponentToExternalReference(ScannedComponent component)
    {
        if (!(component.Component is SpdxComponent))
        {
            throw new ArgumentException($"{nameof(component.Component)} is not an SpdxComponent");
        }

        var sbomComponent = (SpdxComponent)component.Component;

        if (sbomComponent.DocumentNamespace is null)
        {
            throw new ArgumentException($"{nameof(sbomComponent)} should have {nameof(sbomComponent.DocumentNamespace)}");
        }

        return new ExternalDocumentReferenceInfo
        {
            ExternalDocumentName = sbomComponent.Name,
            Checksum = new[] { new Checksum { Algorithm = AlgorithmName.SHA1, ChecksumValue = sbomComponent.Checksum } },
            Path = sbomComponent.Path,
            DocumentNamespace = sbomComponent.DocumentNamespace.ToString(),
            DescribedElementID = sbomComponent.RootElementId
        };
    }
}
