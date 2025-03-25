// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.SignValidator;

/// <summary>
/// Factory class that provides a <see cref="ISignatureValidator"/> implementation based on the
/// current operating system type.
/// </summary>
public class SignatureValidationProvider : ISignatureValidationProvider
{
    private readonly IEnumerable<ISignatureValidator> signValidators;
    private readonly Dictionary<OSPlatform, ISignatureValidator> signValidatorsMap;
    private readonly IOSUtils osUtils;

    public SignatureValidationProvider(IEnumerable<ISignatureValidator> signValidators, IOSUtils osUtils)
    {
        this.signValidators = signValidators ?? throw new ArgumentNullException(nameof(signValidators));
        this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));

        signValidatorsMap = new Dictionary<OSPlatform, ISignatureValidator>();

        this.Init();
    }

    public void Init()
    {
        foreach (var signValidator in signValidators)
        {
            signValidatorsMap[signValidator.SupportedPlatform] = signValidator;
        }
    }

    public ISignatureValidator Get()
    {
        if (signValidatorsMap.TryGetValue(osUtils.GetCurrentOSPlatform(), out var signValidator))
        {
            return signValidator;
        }

        return null;
    }
}
