// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Extensions;

/// <summary>
/// The validator will use this interface to register a manifest parsing library
/// which it will later use to parse a given manifest file.
///
/// The manifest tool uses the name of this library to inject it at runtime. For that, please make sure
/// that the assembly that implements this interface has the word "Manifest" in it.
/// </summary>
public interface IManifestInterface
{
    /// <summary>
    /// This function is called by the validator upon initialization to get all the
    /// manifest versions this library can parse.
    /// </summary>
    /// <returns>An version sorted array in ascending order of
    /// <see cref="ManifestInfo">manifests</see> this library can parse.</returns>
    ManifestInfo[] RegisterManifest();

    /// <summary>
    /// This function parses a given manifest file.
    /// </summary>
    /// <param name="manifest">The string contents of the manifest file.</param>
    /// <returns>The manifest mapped to an instance of a <see cref="ManifestData"/> object.</returns>
    ManifestData ParseManifest(string manifest);

    /// <summary>
    /// Creates a parser object for the given SBOM file stream.
    /// </summary>
    /// <param name="stream">The stream for the SBOM file.</param>
    /// <returns></returns>
    ISbomParser CreateParser(Stream stream);

    /// <summary>
    /// Gets or sets the version of this <see cref="IManifestInterface"/>.
    /// </summary>
    string Version { get; set; }
}
