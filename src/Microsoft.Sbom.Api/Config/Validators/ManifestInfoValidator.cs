// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Api.Manifest;
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
    private readonly HashSet<ManifestInfo> supportedManifestInfos;

    /// <summary>
    /// Production constructor (satisfied by dependency injection)
    /// </summary>
    public ManifestInfoValidator(IAssemblyConfig assemblyConfig, ManifestGeneratorProvider manifestGeneratorProvider)
        : this(assemblyConfig, GetAvailableManifestInfos(manifestGeneratorProvider))
    {
    }

    /// <summary>
    /// Test constructor
    /// </summary>
    public ManifestInfoValidator(IAssemblyConfig assemblyConfig, HashSet<ManifestInfo> supportedManifestInfos)
    : base(typeof(ValidManifestInfoAttribute), assemblyConfig)
    {
        this.supportedManifestInfos = supportedManifestInfos ?? throw new ArgumentNullException(nameof(supportedManifestInfos));
    }

    public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
    {
        if (paramValue is not null && paramValue is List<ManifestInfo> listOfManifestInfos && !supportedManifestInfos.Any(listOfManifestInfos.Contains))
        {
            var providedValues = string.Join(", ", listOfManifestInfos);
            var validManifestInfoa = string.Join(", ", supportedManifestInfos.Select(m => m.ToString()));
            throw new ValidationArgException($"The value '{providedValues}' contains no values supported by the ManifestInfo (-mi) parameter. Please provide supported values. Supported values include: {validManifestInfoa}. The values are case-insensitive.");
        }
    }

    private static HashSet<ManifestInfo> GetAvailableManifestInfos(ManifestGeneratorProvider manifestGeneratorProvider)
    {
        ArgumentNullException.ThrowIfNull(manifestGeneratorProvider, nameof(manifestGeneratorProvider));
        return [.. manifestGeneratorProvider.GetSupportedManifestInfos()];
    }
}
