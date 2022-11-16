// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Ninject;
using PowerArgs;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api
{
    public class SBOMValidator : ISBOMValidator
    {
        private readonly StandardKernel kernel;

        private readonly IWorkflow<SBOMParserBasedValidationWorkflow> sbomParserBasedValidationWorkflow;

        private readonly IRecorder recorder;

        public SBOMValidator(
            IWorkflow<SBOMParserBasedValidationWorkflow>
            sbomParserBasedValidationWorkflow,
            IRecorder recorder)
        {
            kernel = new StandardKernel(new Bindings());
            this.sbomParserBasedValidationWorkflow = sbomParserBasedValidationWorkflow ?? throw new ArgumentNullException(nameof(sbomParserBasedValidationWorkflow));
            this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        }

        public async Task<SBOMValidationResult> ValidateSbomAsync(
            string buildDropPath,
            string outputPath,
            AlgorithmName algorithmName,
            IList<SBOMSpecification> specifications = null,
            string manifestDirPath = default,
            bool validateSignature = false,
            bool ignoreMissing = false,
            string rootPathFilter = default,
            RuntimeConfiguration runtimeConfiguration = default)
        {
            var configuration = ApiConfigurationBuilder.GetConfiguration(
                buildDropPath,
                outputPath,
                specifications,
                algorithmName,
                manifestDirPath,
                validateSignature,
                ignoreMissing,
                rootPathFilter,
                runtimeConfiguration);

            configuration = ValidateConfig(configuration);

            kernel.Bind<IConfiguration>().ToConstant(configuration);

            // This is the generate workflow
            bool isSuccess = await sbomParserBasedValidationWorkflow.RunAsync();
            await recorder.FinalizeAndLogTelemetryAsync();

            var entityErrors = recorder.Errors.Select(error => error.ToEntityError()).ToList();

            return isSuccess;
        }

        private Configuration ValidateConfig(Configuration config)
        {
            var configValidators = kernel.GetAll<ConfigValidator>();
            var configSanitizer = kernel.Get<ConfigSanitizer>();

            foreach (PropertyDescriptor property in TypeDescriptor.GetProperties(config))
            {
                configValidators.ForEach(v =>
                {
                    v.CurrentAction = config.ManifestToolAction;
                    v.Validate(property.DisplayName, property.GetValue(config), property.Attributes);
                });
            }

            configSanitizer.SanitizeConfig(config);
            return config;
        }
    }
}
