// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.SignValidator;

/// <summary>
/// Factory class that provides a <see cref="ISignValidator"/> implementation based on the
/// current operating system type.
/// </summary>
public class SignValidationProvider : ISignValidationProvider
{
    private readonly IEnumerable<ISignValidator> signValidators;
    private readonly Dictionary<OSPlatform, ISignValidator> signValidatorsMap;
    private readonly IOSUtils osUtils;

    public SignValidationProvider(IEnumerable<ISignValidator> signValidators, IOSUtils osUtils)
    {
        this.signValidators = signValidators ?? throw new ArgumentNullException(nameof(signValidators));
        this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));

        signValidatorsMap = new Dictionary<OSPlatform, ISignValidator>();

        this.Init();
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
        if (signValidatorsMap.TryGetValue(osUtils.GetCurrentOSPlatform(), out var signValidator))
        {
            return signValidator;
        }

        return null;
    }
}
