// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Config.Attributes
{
    /// <summary>
    /// Attribute denoting that an <see cref="Configuration" /> property is a Component Detector argument.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    public class ComponentDetectorArgumentAttribute : Attribute
    {
        /// <summary>
        /// Gets the name of the paramter to be specified when passing the value of the target to Component Detection.
        /// </summary>
        public string ParameterName { get; } = string.Empty;

        /// <param name="parameterName">The name of the parameter to be specified when passing this argument to Component Detection.</param>
        public ComponentDetectorArgumentAttribute(string parameterName)
        {
            ParameterName = parameterName;
        }

        public ComponentDetectorArgumentAttribute()
        {
        }
    }
}
