// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Extensions.Entities;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Validators;

/// <summary>
/// Validates if manifest info is valid.
/// </summary>
public class ManifestInfoValidator : ConfigValidator
{
    public ManifestInfoValidator(IAssemblyConfig assemblyConfig)
        : base(typeof(ValidManifestInfoAttribute), assemblyConfig)
    {
    }

    public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
    {
        if (paramValue is not null && paramValue is List<ManifestInfo> listOfManifestInfos && !Constants.SupportedSpdxManifests.Any(listOfManifestInfos.Contains))
        {
            var supportedManifests = string.Join(", ", Constants.SupportedSpdxManifests.Select(m => m.ToString()));
            throw new ValidationArgException($"Please provide a valid value for the ManifestInfo (-mi) parameter. Supported values include: {supportedManifests}. The values are case-insensitive.");
        }
    }
}
