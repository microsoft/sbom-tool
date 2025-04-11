// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Utils;

public class SbompackageComparer : IEqualityComparer<SbomPackage>
{
    public bool Equals(SbomPackage package1, SbomPackage package2)
    {
        if (package1 == null || package2 == null)
        {
            return false;
        }

        var checksumsEqual = (package1.Checksum == null && package2.Checksum == null) ||
                         package1.Checksum?.SequenceEqual(package2.Checksum ?? Enumerable.Empty<Checksum>()) == true;

        // Compare relevant fields.
        // Note: FilesAnalyzed is not compared as it is not relevant for equality since it's not a valid field in SPDX 3.0.
        return package1.Id == package2.Id &&
               package1.PackageName == package2.PackageName &&
               package1.PackageVersion == package2.PackageVersion &&
               package1.PackageUrl == package2.PackageUrl &&
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
        if (obj == null)
        {
            return 0;
        }

        return obj.Id.GetHashCode();
    }
}
