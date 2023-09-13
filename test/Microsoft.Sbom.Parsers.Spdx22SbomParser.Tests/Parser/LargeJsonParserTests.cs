// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JsonStreaming;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class LargeJsonParserTests
{
    [TestMethod]
    public async Task ParseLargeJson()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.GoodJsonWith3PackagesString);
        using var stream = new MemoryStream(bytes);

        var parser = new BadParser(stream);

        _ = await Assert.ThrowsExceptionAsync<ParserException>(() => parser.ParseAsync(CancellationToken.None));
    }

    private class BadParser : NewSPDXParser
    {
        public BadParser(Stream stream)
            : base(stream)
        {
        }

        public int PackageCount { get; private set; }

        public override Task HandleFilesAsync(IEnumerable<SbomFile> files, CancellationToken cancellationToken) => throw new NotImplementedException();

        public override Task HandlePackagesAsync(IEnumerable<SbomPackage> packages, CancellationToken cancellationToken)
        {
            packages.GetEnumerator().MoveNext();
            return Task.CompletedTask;
        }

        public override Task HandleReferencesAsync(IEnumerable<SBOMReference> references, CancellationToken cancellationToken) => throw new NotImplementedException();

        public override Task HandleRelationshipsAsync(IEnumerable<SBOMRelationship> relationships, CancellationToken cancellationToken) => throw new NotImplementedException();
    }
}
