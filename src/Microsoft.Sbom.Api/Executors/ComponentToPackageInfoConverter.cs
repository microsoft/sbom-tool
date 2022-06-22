﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Adapters.Adapters.ComponentDetection;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Contracts;
using Serilog;
using System;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Takes a <see cref="ScannedComponent"/> object and converts it to a <see cref="PackageInfo"/>
    /// object using a <see cref="IPackageInfoConverter"/>.
    /// </summary>
    public class ComponentToPackageInfoConverter
    {
        private readonly ILogger log;

        // TODO: Remove and use interface
        // For unit testing only
        public ComponentToPackageInfoConverter() { }

        public ComponentToPackageInfoConverter(ILogger log)
        {
            this.log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public virtual (ChannelReader<SBOMPackage> output, ChannelReader<FileValidationResult> errors) Convert(ChannelReader<ScannedComponent> componentReader)
        {
            var output = Channel.CreateUnbounded<SBOMPackage>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            Task.Run(async () =>
            {
                var report = new AdapterReport();
                await foreach (ScannedComponent scannedComponent in componentReader.ReadAllAsync())
                {
                    await ConvertComponentToPackage(scannedComponent, output, errors);
                }

                output.Writer.Complete();
                errors.Writer.Complete();

                async Task ConvertComponentToPackage(ScannedComponent scannedComponent, Channel<SBOMPackage> output, Channel<FileValidationResult> errors)
                {
                    try
                    {
                        var sbom = scannedComponent.ToSbomPackage(report);
                        await output.Writer.WriteAsync(sbom);
                    }
                    catch (Exception e)
                    {
                        log.Debug($"Encountered an error while processing package {scannedComponent.Component.Id}: {e.Message}");
                        await errors.Writer.WriteAsync(new FileValidationResult
                        {
                            ErrorType = ErrorType.PackageError,
                            Path = scannedComponent.LocationsFoundAt.FirstOrDefault()
                        });
                    }
                }
            });

            return (output, errors);
        }
    }
}