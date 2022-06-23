﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Microsoft.Sbom.Api.Utils.Tests
{
    [TestClass]
    public class IdentifierUtilsTests
    {
        [TestMethod]
        public void TryGetGuidFromShortGuidTest_Succeeds()
        {
            var shortGuid = IdentifierUtils.GetShortGuid(Guid.NewGuid());
            Assert.IsNotNull(shortGuid);

            Assert.IsTrue(IdentifierUtils.TryGetGuidFromShortGuid(shortGuid, out Guid guid));
            Assert.IsFalse(guid.Equals(Guid.Empty));
        }

        [TestMethod]
        public void TryGetGuidFromShortGuidTest_BadString_Fails_DoesntThrow()
        {
            Assert.IsFalse(IdentifierUtils.TryGetGuidFromShortGuid(string.Empty, out Guid guid1));
            Assert.IsTrue(guid1.Equals(Guid.Empty));

            Assert.IsFalse(IdentifierUtils.TryGetGuidFromShortGuid(null, out Guid guid2));
            Assert.IsTrue(guid2.Equals(Guid.Empty));

            Assert.IsFalse(IdentifierUtils.TryGetGuidFromShortGuid("asdf", out Guid guid3));
            Assert.IsTrue(guid3.Equals(Guid.Empty));
        }
    }
}