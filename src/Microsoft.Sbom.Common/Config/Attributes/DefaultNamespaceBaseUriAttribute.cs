// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config.Attributes;

[AttributeUsage(AttributeTargets.Assembly)]
public class DefaultNamespaceBaseUriAttribute : Attribute
{
    /// <summary>
    /// Gets or sets the default value for the namespace base URI.
    /// </summary>
    public string DefaultBaseNamespaceUri { get; set; }

    public DefaultNamespaceBaseUriAttribute(string defaultBaseNamespaceUri)
    {
        if (string.IsNullOrEmpty(defaultBaseNamespaceUri))
        {
            throw new ArgumentException($"'{nameof(defaultBaseNamespaceUri)}' cannot be null or empty.", nameof(defaultBaseNamespaceUri));
        }

        DefaultBaseNamespaceUri = defaultBaseNamespaceUri;
    }
}
