// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api
{
    /// <summary>
    /// Responsible for an API to generate SBOMs.
    /// </summary>
    public class SBOMGenerator : ISBOMGenerator
    {
        private readonly IWorkflow<SBOMGenerationWorkflow> generationWorkflow;
        private readonly ManifestGeneratorProvider generatorProvider;
        private readonly IRecorder recorder;

        public SBOMGenerator(IWorkflow<SBOMGenerationWorkflow> generationWorkflow, ManifestGeneratorProvider generatorProvider, IRecorder recorder)
        {
            this.generationWorkflow = generationWorkflow;
            this.generatorProvider = generatorProvider;
            this.recorder = recorder;
        }

        /// <inheritdoc />
        public async Task<SBOMGenerationResult> GenerateSBOMAsync()
        {
            bool isSuccess = await generationWorkflow.RunAsync();

            // TODO: Telemetry?
            await recorder.FinalizeAndLogTelemetryAsync();

            var entityErrors = recorder.Errors.Select(error => error.ToEntityError()).ToList();

            return new SBOMGenerationResult(isSuccess, entityErrors);
        }

        /// <inheritdoc />
        public IEnumerable<AlgorithmName> GetRequiredAlgorithms(SBOMSpecification specification)
        {
            ArgumentNullException.ThrowIfNull(specification);

            // The provider will throw if the generator is not found.
            var generator = generatorProvider.Get(specification.ToManifestInfo());

            return generator
                    .RequiredHashAlgorithms
                    .ToList();
        }

        public IEnumerable<SBOMSpecification> GetSupportedSBOMSpecifications()
        {
            return generatorProvider
                    .GetSupportedManifestInfos()
                    .Select(g => g.ToSBOMSpecification())
                    .ToList();
        }
    }
}
