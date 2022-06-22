// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts;
using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Takes a SBOMPackage object and converts it into a PackageInfo object.
    /// </summary>
    public class SBOMPackageToPackageInfoConverter
    {
        public (ChannelReader<SBOMPackage> ouput, ChannelReader<FileValidationResult> errors) Convert(ChannelReader<SBOMPackage> componentReader)
        {
            if (componentReader is null)
            {
                throw new ArgumentNullException(nameof(componentReader));
            }

            var output = Channel.CreateUnbounded<SBOMPackage>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            Task.Run(async () =>
            {
                await foreach (SBOMPackage component in componentReader.ReadAllAsync())
                {
                    await WritePackageInfo(component, output, errors);
                }

                output.Writer.Complete();
                errors.Writer.Complete();
            });

            return (output, errors);
        }

        private static async Task WritePackageInfo(SBOMPackage component, Channel<SBOMPackage> output, Channel<FileValidationResult> errors)
        {
            try
            {
                var checksums = new List<Checksum>();
                if (component.Checksum != null)
                {
                    foreach (var checksum in component.Checksum)
                    {
                        checksums.Add(new Checksum
                        {
                            Algorithm = checksum.Algorithm,
                            ChecksumValue = checksum.ChecksumValue
                        });
                    }
                }

                var licenceInfo = new LicenseInfo
                {
                    Concluded = component.LicenseInfo?.Concluded,
                    Declared = component.LicenseInfo?.Declared
                };

                var packageInfo = new SBOMPackage
                {
                    Id = component.Id,
                    Checksum = checksums,
                    CopyrightText = component.CopyrightText,
                    FilesAnalyzed = component.FilesAnalyzed,
                    LicenseInfo = licenceInfo,
                    PackageName = component.PackageName,
                    PackageUrl = component.PackageUrl,
                    PackageSource = component.PackageSource,
                    Supplier = component.Supplier,
                    PackageVersion = component.PackageVersion
                };

                await output.Writer.WriteAsync(packageInfo);
            }
            catch (Exception)
            {
                await errors.Writer.WriteAsync(new FileValidationResult
                {
                    ErrorType = ErrorType.PackageError,
                    Path = component.Id
                });
            }
        }
    }
}
