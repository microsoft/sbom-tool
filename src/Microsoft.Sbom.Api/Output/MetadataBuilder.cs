﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;
using System;
using System.Text.Json;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;

namespace Microsoft.Sbom.Api.Output
{
    /// <summary>
    /// Provides metadata that can be added to an SBOM.
    /// as a header.
    /// </summary>
    public class MetadataBuilder : IMetadataBuilder
    {
        private readonly IManifestGenerator manifestGenerator;
        private readonly ILogger logger;
        private readonly ManifestInfo manifestInfo;
        private readonly IRecorder recorder;

        public MetadataBuilder(
            ILogger logger,
            ManifestGeneratorProvider manifestGeneratorProvider,
            ManifestInfo manifestInfo,
            IRecorder recorder)
        {
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.manifestInfo = manifestInfo ?? throw new ArgumentNullException(nameof(manifestInfo));
            manifestGenerator = manifestGeneratorProvider
                    .Get(manifestInfo);
            this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        }

        /// <summary>
        /// Gets the json string value of the header dictionary.
        /// </summary>
        /// <returns></returns>
        public string GetHeaderJsonString(IInternalMetadataProvider internalMetadataProvider)
        {
            using (recorder.TraceEvent(string.Format(Events.MetadataBuilder, manifestInfo)))
            {
                logger.Debug("Building the header object.");
                var headerDictionary = manifestGenerator.GetMetadataDictionary(internalMetadataProvider);
                return JsonSerializer.Serialize(headerDictionary);
            }
        }

        public bool TryGetFilesArrayHeaderName(out string headerName)
        {
            try
            {
                headerName = manifestGenerator.FilesArrayHeaderName;
                return true;
            }
            catch (NotSupportedException)
            {
                headerName = null;
                logger.Debug("Files array not suppored on this SBOM format.");
                return false;
            }
        }

        public bool TryGetPackageArrayHeaderName(out string headerName)
        {
            try
            {
                headerName = manifestGenerator.PackagesArrayHeaderName;
                return true;
            }
            catch (NotSupportedException)
            {
                headerName = null;
                logger.Debug("Packages array not suppored on this SBOM format.");
                return false;
            }
        }

        public bool TryGetExternalRefArrayHeaderName(out string headerName)
        {
            try
            {
                headerName = manifestGenerator.ExternalDocumentRefArrayHeaderName;
                return true;
            }
            catch (NotSupportedException)
            {
                headerName = null;
                logger.Debug("External Document Reference array not suppored on this SBOM format.");
                return false;
            }
        }

        public bool TryGetRootPackageJson(IInternalMetadataProvider internalMetadataProvider, out GenerationResult generationResult)
        {
            try
            {
                generationResult = manifestGenerator
                                    .GenerateRootPackage(internalMetadataProvider);

                if (generationResult == null)
                {
                    return false;
                }

                return true;
            }
            catch (NotSupportedException)
            {
                generationResult = null;
                logger.Debug("Root package serialization not supported on this SBOM format.");
                return false;
            }
        }

        public bool TryGetRelationshipsHeaderName(out string headerName)
        {
            try
            {
                headerName = manifestGenerator.RelationshipsArrayHeaderName;
                return headerName != null;
            }
            catch (NotSupportedException)
            {
                headerName = null;
                logger.Debug("Relationships array are not supported on this SBOM format.");
                return false;
            }
        }
    }
}
