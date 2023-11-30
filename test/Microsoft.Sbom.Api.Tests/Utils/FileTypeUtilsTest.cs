// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Api.Tests.Utils;

[TestClass]
public class FileTypeUtilsTest
{
    private readonly FileTypeUtils fileTypeUtils = new FileTypeUtils();

    [TestMethod]
    public void When_GetFileTypeBy_WithSpdxFile_ThenReturnSPDXType()
    {
        var types = fileTypeUtils.GetFileTypesBy("random.spdx.json");
        Assert.AreEqual(1, types.Count);
        Assert.AreEqual(FileType.SPDX, types[0]);
    }

    [TestMethod]
    public void When_GetFileTypeBy_WithNonNullFile_ThenReturnNull()
    {
        var types = fileTypeUtils.GetFileTypesBy("random");
        Assert.IsNull(types);
    }

    [TestMethod]
    public void When_GetFileTypeBy_WithNullFile_ThenReturnNull()
    {
        var types = fileTypeUtils.GetFileTypesBy(null);
        Assert.IsNull(types);
    }
}
