// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.ComponentModel;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Utils.Tests
{
    [TestClass]
    public class IdentityUtilsTests
    {
        [TestMethod]
        public void GetGenerationTimestamp_Default_Test()
        {
            var mdProviderMock = new Mock<IInternalMetadataProvider>();
            object time = null;
            mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.GenerationTimestamp, out time))
                .Returns(false);

            var identityUtils = new IdentityUtils();
            var timestamp = identityUtils.GetGenerationTimestamp(mdProviderMock.Object);

            Assert.IsNotNull(timestamp);
            var parsedDate = new DateTimeOffsetConverter().ConvertFromString(timestamp);
            Assert.IsNotNull(parsedDate);
        }

        [TestMethod]
        public void GetGenerationTimestamp_Override_Test()
        {
            var mdProviderMock = new Mock<IInternalMetadataProvider>();
            object time = "time";
            mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.GenerationTimestamp, out time))
                .Returns(true);

            var identityUtils = new IdentityUtils();
            var timestamp = identityUtils.GetGenerationTimestamp(mdProviderMock.Object);

            Assert.IsNotNull(timestamp);
            Assert.IsTrue(timestamp.Equals("time"));
        }
    }
}