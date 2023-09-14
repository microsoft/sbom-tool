// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using JsonStreaming;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class LargeJsonParserTests
{
    [TestMethod]
    public void LargeJsonParser_RequiresFullEnumeration()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.GoodJsonWith3PackagesString);
        using var stream = new MemoryStream(bytes);

        var parser = new NewSPDXParser(stream);

        var result = parser.Next();
        Assert.AreEqual(NewSPDXParser.PackagesProperty, result.FieldName);
        if (result.Result is IEnumerable enumerable)
        {
            Assert.IsNotNull(enumerable);
            Assert.IsTrue(enumerable.GetEnumerator().MoveNext());

            _ = Assert.ThrowsException<ParserException>(() => parser.Next());
        }
        else
        {
            Assert.Fail();
        }
    }
}