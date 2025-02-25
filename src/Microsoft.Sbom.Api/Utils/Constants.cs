// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Utils;

public static class Constants
{
    public static List<Entities.ErrorType> SkipFailureReportingForErrors = new()
    {
        Entities.ErrorType.ManifestFolder,
        Entities.ErrorType.FilteredRootPath,
        Entities.ErrorType.ReferencedSbomFile,
    };
}
