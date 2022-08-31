// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Config;

using Ninject.Activation;
using Serilog;
using Serilog.Core;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Logging
{
    /// <summary>
    /// Configures and returns a <see cref="ILogger"/> object.
    /// </summary>
    public class LoggerProvider : Provider<ILogger>
    {
        private readonly IConfiguration configuration;

        public LoggerProvider(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        protected override ILogger CreateInstance(IContext context)
        {
            return new LoggerConfiguration()
                .MinimumLevel.ControlledBy(new LoggingLevelSwitch { MinimumLevel = configuration.Verbosity.Value })
                .WriteTo.Console(outputTemplate: Constants.LoggerTemplate)
                .CreateLogger();
        }
    }
}
