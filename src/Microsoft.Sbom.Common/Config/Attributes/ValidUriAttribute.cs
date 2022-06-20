using Microsoft.Sbom.Common.Config;
using System;

namespace Microsoft.Sbom.Api.Attributes
{
    /// <summary>
    /// Validate if the property value is a valid URI.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Assembly, Inherited = false, AllowMultiple = false)]
    public sealed class ValidUriAttribute : Attribute
    {
        /// <summary>
        /// Execute this validation only for the given action. Default is all.
        /// </summary>
        public ManifestToolActions ForAction { get; set; }

        /// <summary>
        /// The type of URI the value should be.
        /// </summary>
        public UriKind UriKind { get; set; }

        public ValidUriAttribute()
        {
            ForAction = ManifestToolActions.Generate;
        }
    }
}
