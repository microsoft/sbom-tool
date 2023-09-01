// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Common.Config.Validators;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Validators;

/// <summary>
/// Validates if a value is a valid URI.
/// </summary>
public class UriValidator : ConfigValidator
{
    public UriValidator(IAssemblyConfig assemblyConfig)
        : base(typeof(ValidUriAttribute), assemblyConfig)
    {
    }

    public UriValidator(Type supportedAttribute, IAssemblyConfig assemblyConfig)
        : base(supportedAttribute, assemblyConfig)
    {
    }

    public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
    {
        if (attribute != null && attribute is ValidUriAttribute validUriAttribute && validUriAttribute.ForAction.HasFlag(CurrentAction))
        {
            if (paramValue is string value && !string.IsNullOrEmpty(value) && !Uri.IsWellFormedUriString(value, validUriAttribute.UriKind))
            {
                throw new ValidationArgException($"The value of {paramName} must be a valid URI.");
            }
        }
    }
}
