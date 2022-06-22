// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Utils
{
    public interface IFileTypeUtils
    {
        List<FileType> GetFileTypesBy(string fileName);
    }
}
