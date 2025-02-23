// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Takes a SbomFile and converts it to a FileInfo object.
/// </summary>
public class SbomFileToFileInfoConverter
{
    private readonly IFileTypeUtils fileTypeUtils;

    public SbomFileToFileInfoConverter(IFileTypeUtils fileTypeUtils)
    {
        this.fileTypeUtils = fileTypeUtils ?? throw new ArgumentNullException(nameof(fileTypeUtils));
    }

    public (ChannelReader<InternalSbomFileInfo> output, ChannelReader<FileValidationResult> error) Convert(ChannelReader<SbomFile> componentReader, FileLocation fileLocation = FileLocation.OnDisk)
    {
        if (componentReader is null)
        {
            throw new ArgumentNullException(nameof(componentReader));
        }

        var output = Channel.CreateUnbounded<InternalSbomFileInfo>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        Task.Run(async () =>
        {
            await foreach (var component in componentReader.ReadAllAsync())
            {
                await Convert(component, output, errors, fileLocation);
            }

            output.Writer.Complete();
            errors.Writer.Complete();
        });

        return (output, errors);
    }

    private async Task Convert(SbomFile component, Channel<InternalSbomFileInfo> output, Channel<FileValidationResult> errors, FileLocation fileLocation)
    {
        try
        {
            var checksums = new List<Checksum>();
            foreach (var checksum in component.Checksum)
            {
                checksums.Add(new Checksum
                {
                    Algorithm = checksum.Algorithm,
                    ChecksumValue = checksum.ChecksumValue
                });
            }

            var fileInfo = new InternalSbomFileInfo
            {
                Path = component.Path,
                Checksum = checksums.ToArray(),
                FileCopyrightText = component.FileCopyrightText,
                LicenseConcluded = component.LicenseConcluded,
                LicenseInfoInFiles = component.LicenseInfoInFiles,
                FileTypes = fileTypeUtils.GetFileTypesBy(component.Path),
                IsOutsideDropPath = false, // assumption from SbomApi is that Files are in dropPath
                FileLocation = fileLocation,
            };

            await output.Writer.WriteAsync(fileInfo);
        }
        catch (UnsupportedHashAlgorithmException)
        {
            await errors.Writer.WriteAsync(new FileValidationResult
            {
                ErrorType = ErrorType.UnsupportedHashAlgorithm,
                Path = component.Path
            });
        }
        catch (Exception)
        {
            await errors.Writer.WriteAsync(new FileValidationResult
            {
                ErrorType = ErrorType.Other,
                Path = component.Path
            });
        }
    }
}
