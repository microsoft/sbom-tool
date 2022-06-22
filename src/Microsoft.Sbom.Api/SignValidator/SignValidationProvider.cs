// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Serilog;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.SignValidator
{
    /// <summary>
    /// Factory class that provides a <see cref="ISignValidator"/> implementation based on the 
    /// current operating system type.
    /// </summary>
    public class SignValidationProvider
    {
        private readonly ISignValidator[] signValidators;
        private readonly Dictionary<OSPlatform, ISignValidator> signValidatorsMap;
        private readonly ILogger logger;
        private readonly IOSUtils osUtils;

        public SignValidationProvider(ISignValidator[] signValidators, ILogger logger, IOSUtils osUtils)
        {
            this.signValidators = signValidators ?? throw new ArgumentNullException(nameof(signValidators));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));

            signValidatorsMap = new Dictionary<OSPlatform, ISignValidator>();
        }

        public void Init()
        {
            foreach (var signValidator in signValidators)
            {
                signValidatorsMap[signValidator.SupportedPlatform] = signValidator;
            }
        }

        public ISignValidator Get()
        {
            if (!signValidatorsMap.TryGetValue(osUtils.GetCurrentOSPlatform(), out ISignValidator signValidator))
            {
                logger.Error($"No signature validator found for current OS, supported OS are {signValidatorsMap.Keys}");
                throw new SignValidatorNotFoundException("No signature validator found for current OS");
            }

            return signValidator;
        }
    }
}
