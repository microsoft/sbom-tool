// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Linq;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using SbomChecksum = Microsoft.Sbom.Contracts.Checksum;

namespace Microsoft.Sbom.Utils;

/// <summary>
/// Provides extension methods to convert a SPDX object to
/// the equivalent internal object as defined in Sbom.Contracts.
/// </summary>
public static class SPDXToSbomFormatConverterExtensions
{
    /// <summary>
    /// Converts a <see cref="SPDXFile"/> object to a <see cref="SbomFile"/> object.
    /// </summary>
    /// <param name="spdxFile"></param>
    /// <returns></returns>
    public static SbomFile ToSbomFile(this File spdxFile)
    {
        var checksums = spdxFile.VerifiedUsing?.Select(c => c.ToSbomChecksum());

        // Not setting LicenseConcluded and LicenseInfoInFiles since the whole SBOM is required to set these values.
        return new SbomFile
        {
            Checksum = checksums,
            FileCopyrightText = spdxFile.CopyrightText,
            Id = spdxFile.SpdxId,
            Path = spdxFile.Name
        };
    }

    /// <summary>
    /// Convert a <see cref="SPDXChecksum"/> object to a <see cref="SbomChecksum"/> object.
    /// </summary>
    /// <param name="spdxPackageVerificationCode"></param>
    /// <returns></returns>
    internal static SbomChecksum ToSbomChecksum(this PackageVerificationCode spdxPackageVerificationCode)
    {
        if (spdxPackageVerificationCode is null)
        {
            return null;
        }

        return new SbomChecksum
        {
            Algorithm = AlgorithmName.FromString(spdxPackageVerificationCode.Algorithm.ToString()),
            ChecksumValue = spdxPackageVerificationCode.HashValue,
        };
    }
}
