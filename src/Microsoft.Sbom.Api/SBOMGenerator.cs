// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Ninject;

namespace Microsoft.Sbom.Api
{
    /// <summary>
    /// Responsible for an API to generate SBOMs.
    /// </summary>
    public class SBOMGenerator : ISBOMGenerator
    {
        private readonly StandardKernel kernel;
        private readonly IFileSystemUtils fileSystemUtils;

        public SBOMGenerator()
        {
            kernel = new StandardKernel(new Bindings());
            fileSystemUtils = new WindowsFileSystemUtils();
        }

        public SBOMGenerator(StandardKernel kernel, IFileSystemUtils fileSystemUtils)
        {
            this.kernel = kernel ?? throw new ArgumentNullException(nameof(kernel));
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        }

        /// <inheritdoc />
        public async Task<SBOMGenerationResult> GenerateSBOMAsync(
            string rootPath,
            string componentPath,
            SBOMMetadata metadata,
            IList<SBOMSpecification> specifications = null,
            RuntimeConfiguration configuration = null,
            string manifestDirPath = null,
            string externalDocumentReferenceListFile = null)
        {
            // Get scan configuration
            var config = ApiConfigurationBuilder.GetConfiguration(
                rootPath,
                manifestDirPath, null, null, metadata, specifications,
                configuration, externalDocumentReferenceListFile, componentPath);

            // Initialize the IOC container. This varies depending on the configuration.
            config = ValidateConfig(config);
            kernel.Bind<IConfiguration>().ToConstant(config);

            // This is the generate workflow
            IWorkflow<SBOMGenerationWorkflow> workflow = kernel.Get<IWorkflow<SBOMGenerationWorkflow>>(nameof(SBOMGenerationWorkflow));
            bool isSuccess = await workflow.RunAsync();

            // TODO: Telemetry?
            IRecorder recorder = kernel.Get<IRecorder>();
            await recorder.FinalizeAndLogTelemetryAsync();

            var entityErrors = recorder.Errors.Select(error => error.ToEntityError()).ToList();

            return new SBOMGenerationResult(isSuccess, entityErrors);
        }

        /// <inheritdoc />
        public async Task<SBOMGenerationResult> GenerateSBOMAsync(
            string rootPath,
            IEnumerable<SBOMFile> files,
            IEnumerable<SBOMPackage> packages,
            SBOMMetadata metadata,
            IList<SBOMSpecification> specifications = null,
            RuntimeConfiguration runtimeConfiguration = null,
            string manifestDirPath = null,
            string externalDocumentReferenceListFile = null)
        {
            if (string.IsNullOrWhiteSpace(rootPath))
            {
                throw new ArgumentException($"'{nameof(rootPath)}' cannot be null or whitespace.", nameof(rootPath));
            }

            if (files is null)
            {
                throw new ArgumentNullException(nameof(files));
            }

            if (packages is null)
            {
                throw new ArgumentNullException(nameof(packages));
            }

            if (metadata is null)
            {
                throw new ArgumentNullException(nameof(metadata));
            }

            if (string.IsNullOrWhiteSpace(manifestDirPath))
            {
                manifestDirPath = rootPath;
            }

            var configuration = ApiConfigurationBuilder.GetConfiguration(
                rootPath, manifestDirPath, files, packages, metadata, specifications,
                runtimeConfiguration, externalDocumentReferenceListFile);
            configuration = ValidateConfig(configuration);

            kernel.Bind<IConfiguration>().ToConstant(configuration);

            kernel.Bind<SBOMMetadata>().ToConstant(metadata);
            bool result = await kernel.Get<IWorkflow<SBOMGenerationWorkflow>>(nameof(SBOMGenerationWorkflow)).RunAsync();
            return new SBOMGenerationResult(result, new List<EntityError>());
        }

        /// <inheritdoc />
        public IEnumerable<AlgorithmName> GetRequiredAlgorithms(SBOMSpecification specification)
        {
            if (specification is null)
            {
                throw new ArgumentNullException(nameof(specification));
            }

            var generatorProvider = kernel.Get<ManifestGeneratorProvider>();
            if (generatorProvider == null)
            {
                throw new MissingGeneratorException($"Unable to get a list of supported SBOM generators.");
            }

            // The provider will throw if the generator is not found.
            var generator = generatorProvider.Get(specification.ToManifestInfo());

            return generator
                        .RequiredHashAlgorithms
                        .ToList();
        }

        public IEnumerable<SBOMSpecification> GetSupportedSBOMSpecifications()
        {
            var generatorProvider = kernel.Get<ManifestGeneratorProvider>();
            if (generatorProvider == null)
            {
                throw new Exception($"Unable to get a list of supported SBOM generators.");
            }

            return generatorProvider
                    .GetSupportedManifestInfos()
                    .Select(g => g.ToSBOMSpecification())
                    .ToList();
        }

        private Configuration ValidateConfig(Configuration config)
        {
            var configValidators = kernel.GetAll<ConfigValidator>();
            var configSanitizer = kernel.Get<ConfigSanitizer>();

            foreach (PropertyDescriptor property in TypeDescriptor.GetProperties(config))
            {
                foreach (var v in configValidators)
                {
                    v.CurrentAction = config.ManifestToolAction;
                    v.Validate(property.DisplayName, property.GetValue(config), property.Attributes);
                }
            }

            configSanitizer.SanitizeConfig(config);
            return config;
        }
    }
}
