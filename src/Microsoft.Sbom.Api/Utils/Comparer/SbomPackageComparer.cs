// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Utils.Comparer;

public class SbomPackageComparer : IEqualityComparer<SbomPackage>
{
    private static readonly SbomChecksumComparer ChecksumComparer = new SbomChecksumComparer();

    public bool Equals(SbomPackage package1, SbomPackage package2)
    {
        if (package1 is null || package2 is null)
        {
            return false;
        }

        // Normalize PackageUrl for root packages since the SBOM tool version will vary between SPDX 2.2 and SPDX 3.0.
        // Also normalize the Checksum since SPDX 2.2 does not support PackageVerificationCode to Checksum conversions for Root packages.
        var normalizedPackage1Url = package1.PackageUrl;
        var normalizedPackage2Url = package2.PackageUrl;

        var package1Checksum = package1.Checksum;
        var package2Checksum = package2.Checksum;
        if (package1.Id == Constants.RootPackageIdValue && package2.Id == Constants.RootPackageIdValue)
        {
            normalizedPackage1Url = NormalizePackagePurl(package1);
            normalizedPackage2Url = NormalizePackagePurl(package2);

            package1Checksum = null;
            package2Checksum = null;
        }

        var checksumsEqual = (package1Checksum is null && package2Checksum is null) ||
                         package1Checksum?.SequenceEqual(package2Checksum ?? Enumerable.Empty<Checksum>(), ChecksumComparer) is true;

        // Compare relevant fields.
        // Note: FilesAnalyzed is not compared as it is not relevant for equality since it's not a valid field in SPDX 3.0.
        return package1.Id == package2.Id &&
               package1.PackageName == package2.PackageName &&
               package1.PackageVersion == package2.PackageVersion &&
               normalizedPackage1Url == normalizedPackage2Url &&
               package1.PackageSource == package2.PackageSource &&
               package1.CopyrightText == package2.CopyrightText &&
               package1.LicenseInfo.Declared == package2.LicenseInfo.Declared &&
               package1.LicenseInfo.Concluded == package2.LicenseInfo.Concluded &&
               package1.Supplier == package2.Supplier &&
               package1.Type == package2.Type &&
               package1.DependOn == package2.DependOn &&
               checksumsEqual;
    }

    public int GetHashCode(SbomPackage obj)
    {
        if (obj is null)
        {
            return 0;
        }

        return obj.Id.GetHashCode();
    }

    private string NormalizePackagePurl(SbomPackage package)
    {
        var packageUrl = package?.PackageUrl;
        if (!string.IsNullOrEmpty(packageUrl))
        {
            // Remove everything after the '=' character
            var index = packageUrl.IndexOf('=');
            var normalizedPackageUrl = index >= 0 ? packageUrl.Substring(0, index) : packageUrl;
            return normalizedPackageUrl;
        }

        return packageUrl;
    }
}
