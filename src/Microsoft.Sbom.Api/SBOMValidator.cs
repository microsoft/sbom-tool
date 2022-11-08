using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Ninject;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api
{
    public class SBOMValidator : ISBOMValidator
    {
        private StandardKernel kernel;
        private ApiConfigurationBuilder configurationBuilder;

        public SBOMValidator()
        {
            kernel = new StandardKernel(new Bindings());
            configurationBuilder = new ApiConfigurationBuilder();            
        }

        public async Task<bool> ValidateSbomAsync(
            string buildDropPath,
            string outputPath,
            AlgorithmName algorithmName,
            string manifestDirPath,
            string catalogFilePath,
            bool validateSignature,
            bool ignoreMissing,
            string rootPathFilter,
            RuntimeConfiguration runtimeConfiguration)
        {
            var configuration = configurationBuilder.GetConfiguration(
                buildDropPath,
                outputPath,
                algorithmName,
                manifestDirPath,
                catalogFilePath,
                validateSignature,
                ignoreMissing,
                rootPathFilter,
                runtimeConfiguration);

            kernel.Bind<IConfiguration>().ToConstant(configuration);

            // This is the generate workflow
            IWorkflow workflow = kernel.Get<IWorkflow>(nameof(SBOMParserBasedValidationWorkflow));
            bool isSuccess = await workflow.RunAsync();

            IRecorder recorder = kernel.Get<IRecorder>();
            await recorder.FinalizeAndLogTelemetryAsync();

            var entityErrors = ((TelemetryRecorder)recorder).Errors.Select(error => error.ToEntityError()).ToList();

            return isSuccess;
        }
    }
}
