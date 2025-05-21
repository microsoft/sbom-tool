// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Api.Utils;

public interface IFileTypeUtils
{
    public List<FileType> GetFileTypesBy(string fileName);
}
