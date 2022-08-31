// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using System;

using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Config.Attributes;

namespace Microsoft.Sbom.Api.Config.Validators
{
    /// <summary>
    /// Validates if the integer property is in the provided inclusive range.
    /// </summary>
    public class IntRangeValidator : ConfigValidator
    {
        public IntRangeValidator(IAssemblyConfig assemblyConfig)
            : base(typeof(IntRangeAttribute), assemblyConfig)
        {
        }

        public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
        {
            if (paramValue != null && paramValue is int value)
            {
                IntRangeAttribute intRangeAttribute = attribute as IntRangeAttribute;

                if (value < intRangeAttribute.MinRange || value > intRangeAttribute.MaxRange)
                {
                    throw new ValidationArgException($"The value for {paramName} should be equal to or between {intRangeAttribute.MinRange} and {intRangeAttribute.MaxRange}");
                }
            }
        }
    }
}
