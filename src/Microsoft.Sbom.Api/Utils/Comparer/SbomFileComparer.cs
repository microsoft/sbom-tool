// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Utils.Comparer;

public class SbomFileComparer : IEqualityComparer<SbomFile>
{
    private static readonly SbomChecksumComparer ChecksumComparer = new SbomChecksumComparer();

    public bool Equals(SbomFile file1, SbomFile file2)
    {
        if (file1 is null || file2 is null)
        {
            return false;
        }

        var licenseInfosEqual = (file1.LicenseInfoInFiles is null && file2.LicenseInfoInFiles is null) ||
                        file1.LicenseInfoInFiles?.SequenceEqual(file2.LicenseInfoInFiles ?? Enumerable.Empty<string>()) == true;
        var checksumsEqual = (file1.Checksum is null && file2.Checksum is null) ||
                         file1.Checksum?.SequenceEqual(file2.Checksum ?? Enumerable.Empty<Checksum>(), ChecksumComparer) is true;

        // Compare relevant fields
        return file1.Id == file2.Id &&
               file1.Path == file2.Path &&
               file1.FileCopyrightText == file2.FileCopyrightText &&
               file1.LicenseConcluded == file2.LicenseConcluded &&
               licenseInfosEqual &&
               checksumsEqual;
    }

    public int GetHashCode(SbomFile obj)
    {
        if (obj is null)
        {
            return 0;
        }

        return obj.Id.GetHashCode();
    }
}
