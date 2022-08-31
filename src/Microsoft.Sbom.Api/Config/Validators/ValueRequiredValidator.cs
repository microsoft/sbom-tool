// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using System;

using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Config.Attributes;

namespace Microsoft.Sbom.Api.Config.Validators
{
    /// <summary>
    /// Verifies that the value is not null.
    /// </summary>
    public class ValueRequiredValidator : ConfigValidator
    {
        public ValueRequiredValidator(IAssemblyConfig assemblyConfig)
            : base(typeof(ValueRequiredAttribute), assemblyConfig)
        {
        }

        public ValueRequiredValidator(Type type, IAssemblyConfig assemblyConfig)
            : base(type, assemblyConfig)
        {
        }

        public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
        {
            if (attribute is ValueRequiredAttribute valueRequiredAttribute && !valueRequiredAttribute.ForAction.HasFlag(CurrentAction))
            {
                return;
            }

            if (paramValue == null || (paramValue is string value && string.IsNullOrEmpty(value)))
            {
                throw new ValidationArgException($"The value of {paramName} can't be null or empty.");
            }
        }
    }
}
