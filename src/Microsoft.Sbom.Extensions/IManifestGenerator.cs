// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Extensions;

/// <summary>
/// The manifest tool uses this interface to generate a manifest (JSON format currently)
/// for a given build artifact.
///
/// The manifest tool uses the name of this library to inject it at runtime. For that, please make sure
/// that the dll that implements this interface has the word "Manifest" in it.
/// </summary>
public interface IManifestGenerator
{
    /// <summary>
    /// This function is called by the manifest tool upon initialization to get the
    /// manifest this library can generate.
    /// </summary>
    /// <returns>A <see cref="ManifestInfo">manifest</see> this library can generate.</returns>
    ManifestInfo RegisterManifest();

    /// <summary>
    /// Syncrhonously generates a JSON element from the given fileInfo object.
    ///
    /// The JsonDocument implements <see cref="System.IDisposable"/>, the caller of this function
    /// has the responsibility to dispose this object.
    /// </summary>
    /// <param name="fileInfo">The fileInfo object.</param>
    GenerationResult GenerateJsonDocument(InternalSbomFileInfo fileInfo);

    /// <summary>
    /// Generates a JSON element representation of the <paramref name="packageInfo"/> object.
    ///
    /// The JsonDocument implements <see cref="System.IDisposable"/>, the caller of this function
    /// has the responsibility to dispose this object, so don't use 'using' or dispose this object
    /// in this function.
    /// </summary>
    /// <param name="packageInfo">The current package that needs to be serialized.</param>
    /// <returns></returns>
    GenerationResult GenerateJsonDocument(SbomPackage packageInfo);

    /// <summary>
    /// Generate and return the package this SBOM describes. The <see cref="GenerationData"/> object can be used
    /// to add more information to the final object.
    ///
    /// The JsonDocument implements <see cref="System.IDisposable"/>, the caller of this function
    /// has the responsibility to dispose this object, so don't use 'using' or dispose this object
    /// in this function.
    /// </summary>
    /// <param name="internalMetadataProvider">The <see cref="IInternalMetadataProvider"/> object provides
    /// internal metadata that was generated for this SBOM run.</param>
    /// <param name="rootPackageId">Return the generated root package id.</param>
    /// <returns></returns>
    GenerationResult GenerateRootPackage(IInternalMetadataProvider internalMetadataProvider);

    /// <summary>
    /// Generate and return the JSON relationship information between this SBOM and its elements.
    ///
    /// The JsonDocument implements <see cref="System.IDisposable"/>, the caller of this function
    /// has the responsibility to dispose this object, so don't use 'using' or dispose this object
    /// in this function.
    /// </summary>
    /// <param name="relationship"></param>
    /// <returns></returns>
    GenerationResult GenerateJsonDocument(Relationship relationship);

    /// <summary>
    /// Generate and return the JSON relationship information between this SBOM and external documents such as SBOMs.
    ///
    /// The JsonDocument implements <see cref="System.IDisposable"/>, the caller of this function
    /// has the responsibility to dispose this object, so don't use 'using' or dispose this object
    /// in this function.
    /// </summary>
    /// <param name="externalDocumentReferenceInfo"></param>
    /// <returns></returns>
    GenerationResult GenerateJsonDocument(ExternalDocumentReferenceInfo externalDocumentReferenceInfo);

    /// <summary>
    /// Generate and return the creationInfo element this SBOM describes. The <see cref="GenerationData"/> object can be used
    /// to add more information to the final object.
    /// This applies to only SPDX 3.0 and above.
    /// The JsonDocument implements <see cref="System.IDisposable"/>, the caller of this function
    /// has the responsibility to dispose this object, so don't use 'using' or dispose this object
    /// in this function.
    /// </summary>
    /// <param name="internalMetadataProvider">The <see cref="IInternalMetadataProvider"/> object provides
    /// internal metadata that was generated for this SBOM run.</param>
    /// <returns></returns>
    GenerationResult GenerateJsonDocument(IInternalMetadataProvider internalMetadataProvider);

    /// <summary>
    /// Gets an array of <see cref="AlgorithmName">hash algorithm names</see> this
    /// manifest needs to generate for each file.
    /// </summary>
    AlgorithmName[] RequiredHashAlgorithms { get; }

    /// <summary>
    /// Gets the version of this <see cref="IManifestInterface"/>.
    /// </summary>
    string Version { get; }

    /// <summary>
    /// Return a dictionary of items that need to be added to the header of
    /// the generated SBOM.
    /// </summary>
    /// <param name="internalMetadataProvider">The <see cref="IInternalMetadataProvider"/> object provides
    /// internal metadata that was generated for this SBOM run.</param>
    /// <returns></returns>
    IDictionary<string, object> GetMetadataDictionary(IInternalMetadataProvider internalMetadataProvider);
}
