// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Ninject;
using PowerArgs;
using System;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Config
{
    [ArgDescription("The manifest tool validates or generates a manifest for a build artifact.")]
    [ArgExceptionBehavior(ArgExceptionPolicy.StandardExceptionHandling)]
    [ArgProductName("ManifestTool.exe")]
    public class ManifestToolCmdRunner
    {
        private readonly StandardKernel kernel;

        public ManifestToolCmdRunner()
        {
            IsFailed = false;
            kernel = new StandardKernel(new Bindings());
        }

        public ManifestToolCmdRunner(StandardKernel kernel)
        {
            IsFailed = false;
            this.kernel = kernel ?? throw new ArgumentNullException(nameof(kernel));
        }

        /// <summary>
        /// Gets or sets a value indicating whether displays help info.
        /// </summary>
        [ArgShortcut("?")]
        [ArgShortcut("h")]
        [HelpHook]
        [JsonIgnore]
        [ArgDescription("Prints this help message")]
        public bool Help { get; set; }

        /// <summary>
        /// Gets a value indicating whether if set to true, indicates that there was a problem while parsing the configuration. 
        /// </summary>
        [ArgIgnore]
        public bool IsFailed { get; private set; }

        /// <summary>
        /// Gets a value indicating whether if set to true, indicates that there was a problem accesing a path specified in the parameters.
        /// </summary>
        [ArgIgnore]
        public bool IsAccessError { get; private set; }

        /// <summary>
        /// Validate a build artifact using the manifest. Optionally also verify the signing certificate of the manfiest.
        /// </summary>
        /// <param name="validationArgs"></param>
        [ArgActionMethod]
        [ArgDescription("Validate a build artifact using the manifest. " +
            "Optionally also verify the signing certificate of the manfiest.")]
        public async Task Validate(ValidationArgs validationArgs)
        {
            try
            {
                var mapper = kernel.Get<IMapper>();
                var configFileParser = kernel.Get<ConfigFileParser>();
                var configBuilder = new ConfigurationBuilder<ValidationArgs>(mapper, configFileParser);

                kernel.Bind<IConfiguration>().ToConstant(await configBuilder.GetConfiguration(validationArgs));
                var result = await kernel.Get<IWorkflow>(nameof(SbomToolValidatorWorkflow)).RunAsync();
                await kernel.Get<IRecorder>().FinalizeAndLogTelemetryAsync();

                IsFailed = !result;
            }
            catch (Exception e)
            {
                var message = e.InnerException != null ? e.InnerException.Message : e.Message;
                Console.WriteLine($"Encountered error while running ManifestTool validation workflow. Error: {message}");
                IsFailed = true;
            }
        }

        /// <summary>
        /// Generate a manifest.json and a bsi.json for all the files in the given build drop folder.
        /// </summary>
        [ArgActionMethod]
        [ArgDescription("Generate a manifest.json and a bsi.json for all the files " +
            "in the given build drop folder.")]
        public async Task Generate(GenerationArgs generationArgs)
        {
            try
            {
                var mapper = kernel.Get<IMapper>();
                var configFileParser = kernel.Get<ConfigFileParser>();
                var configBuilder = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

                kernel.Bind<IConfiguration>().ToConstant(await configBuilder.GetConfiguration(generationArgs));

                var result = await kernel.Get<IWorkflow>(nameof(SBOMGenerationWorkflow)).RunAsync();
                await kernel.Get<IRecorder>().FinalizeAndLogTelemetryAsync();
                IsFailed = !result;
            }
            catch (AccessDeniedValidationArgException e)
            {
                var message = e.InnerException != null ? e.InnerException.Message : e.Message;
                Console.WriteLine($"Encountered error while running ManifestTool generation workflow. Error: {message}");
                IsFailed = true;
                IsAccessError = true;
            }
            catch (Exception e)
            {
                var message = e.InnerException != null ? e.InnerException.Message : e.Message;
                Console.WriteLine($"Encountered error while running ManifestTool generation workflow. Error: {message}");
                IsFailed = true;
            }
        }
    }
}
