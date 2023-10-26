// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Utils;

using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.BcdeModels;

public interface IPackageDetailsFactory
{
    ConcurrentDictionary<(string, string), PackageDetailsObject> GetPackageDetailsDictionary(IEnumerable<ScannedComponent> scannedComponents);
}
