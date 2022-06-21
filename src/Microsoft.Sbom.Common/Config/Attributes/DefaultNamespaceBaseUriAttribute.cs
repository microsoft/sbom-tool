// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config.Attributes
{
    [AttributeUsage(AttributeTargets.Assembly)]
    public class DefaultNamespaceBaseUriAttribute : Attribute
    {
        /// <summary>
        /// The default value for the namespace base URI.
        /// </summary>
        public string DefaultBaseNamespaceUri { get; set; }

        /// <summary>
        /// The warning to display to the user if they provide a value in the 
        /// NamespaceUriBase parameter in IConfiguration, since we will be overriding
        /// this value.
        /// </summary>
        public string WarningMessage { get; set; }

        public DefaultNamespaceBaseUriAttribute(string defaultBaseNamespaceUri, string warningMessage)
        {
            if (string.IsNullOrEmpty(defaultBaseNamespaceUri))
            {
                throw new ArgumentException($"'{nameof(defaultBaseNamespaceUri)}' cannot be null or empty.", nameof(defaultBaseNamespaceUri));
            }

            if (string.IsNullOrEmpty(warningMessage))
            {
                throw new ArgumentException($"'{nameof(warningMessage)}' cannot be null or empty.", nameof(warningMessage));
            }

            DefaultBaseNamespaceUri = defaultBaseNamespaceUri;
            WarningMessage = warningMessage;
        }
    }
}
