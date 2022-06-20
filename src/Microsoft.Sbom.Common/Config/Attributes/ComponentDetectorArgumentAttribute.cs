using System;

namespace Microsoft.Sbom.Common.Config.Attributes
{
    /// <summary>
    /// Attribute denoting that an <see cref="Microsoft.Sbom.Api.Config.Configuration" /> property is a Component Detector argument.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    public class ComponentDetectorArgumentAttribute : Attribute
    {
        /// <summary>
        /// The name of the paramter to be specified when passing the value of the target to Component Detection.
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
