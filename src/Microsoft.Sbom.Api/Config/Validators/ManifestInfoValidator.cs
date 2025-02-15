// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Constants;
using Microsoft.Sbom.Extensions.Entities;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Validators;

/// <summary>
/// Validates if manifest info is valid.
/// </summary>
public class ManifestInfoValidator : ConfigValidator
{
    public ManifestInfoValidator(IAssemblyConfig assemblyConfig)
        : base(typeof(ValidUriAttribute), assemblyConfig)
    {
    }

    public ManifestInfoValidator(Type supportedAttribute, IAssemblyConfig assemblyConfig)
        : base(supportedAttribute, assemblyConfig)
    {
    }

    public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
    {
        if (paramValue is not null && paramValue is ManifestInfo manifestInfo && !SpdxConstants.SupportedSpdxManifests.Contains(paramValue as ManifestInfo))
        {
            throw new ValidationArgException($"The value of {paramName} must be a valid ManifestInfo. Supported SPDX versions include 2.2 and 3.0.");
        }
    }
}
