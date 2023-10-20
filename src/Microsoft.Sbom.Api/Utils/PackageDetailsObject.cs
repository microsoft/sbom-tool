// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Utils;

public class PackageDetailsObject
{
    // Define an object that has 2 properties - License and Supplier
    public string License { get; set; }

    public string Supplier { get; set; }
}
