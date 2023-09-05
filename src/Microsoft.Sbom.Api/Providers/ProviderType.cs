// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Providers;

/// <summary>
/// The type of provider for a given source.
/// </summary>
public enum ProviderType
{
    /// <summary>
    /// Packages provider
    /// </summary>
    Packages,

    /// <summary>
    /// Files provider.
    /// </summary>
    Files,

    /// <summary>
    /// External Document Reference provider.
    /// </summary>
    ExternalDocumentReference
}
