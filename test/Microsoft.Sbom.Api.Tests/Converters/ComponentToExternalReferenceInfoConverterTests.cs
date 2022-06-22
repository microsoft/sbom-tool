// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Api.Converters;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;

namespace Microsoft.Sbom.Api.Tests.Converters
{
    [TestClass]
    public class ComponentToExternalReferenceInfoConverterTests
    {
        private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();

        [TestMethod]
        public async Task When_ConvertingComponentToExternalDocRefInfo_WithCommonCase_ThenTestPass()
        {

            var scannedComponents = from i in Enumerable.Range(1, 5)
                                    select new ScannedComponent
                                    {
                                        Component = new SpdxComponent("SPDX-2.2", new Uri("http://test.uri"), $"sbom{i}", "123", $"elementId{i}", $"path{i}")
                                    };

            var componentsChannel = Channel.CreateUnbounded<ScannedComponent>();
            foreach (var component in scannedComponents)
            {
                await componentsChannel.Writer.WriteAsync(component);
            }

            componentsChannel.Writer.Complete();

            var converter = new ComponentToExternalReferenceInfoConverter(mockLogger.Object);
            var (results, errors) = converter.Convert(componentsChannel);

            var refs = await results.ReadAllAsync().ToListAsync();

            await foreach (FileValidationResult error in errors.ReadAllAsync())
            {
                Assert.Fail($"Caught exception: {error.ErrorType}");
            }

            var index = 1;
            foreach (var reference in refs)
            {
                Assert.AreEqual($"sbom{index}", reference.ExternalDocumentName);
                Assert.AreEqual(new Uri("http://test.uri").ToString(), reference.DocumentNamespace);
                Assert.AreEqual($"elementId{index}", reference.DescribedElementID);
                Assert.AreEqual($"path{index}", reference.Path);
                Assert.AreEqual("123", reference.Checksum.First().ChecksumValue);

                index++;
            }
            Assert.AreEqual(scannedComponents.ToList().Count, index - 1);
        }

        [TestMethod]
        public async Task When_ConvertingComponentToExternalDocRefInfo_WithWrongComponentType_ThenTestPass()
        {
            var scannnedComponent1 = new ScannedComponent
            {
                LocationsFoundAt = "test".Split(),
                Component = new SpdxComponent("SPDX-2.2", new Uri("http://test.uri"), "sbom1", "123", "abcdef", "path1")
            };
            var scannnedComponent2 = new ScannedComponent
            {
                LocationsFoundAt = "test".Split(),
                Component = new SpdxComponent("SPDX-2.2", new Uri("http://test.uri"), "sbom2", "123", "abcdef", "path2")
            };
            var scannnedComponent3 = new ScannedComponent
            {
                LocationsFoundAt = "test".Split(),
                Component = new SpdxComponent("SPDX-2.2", new Uri("http://test.uri"), "sbom3", "123", "abcdef", "path3")
            };
            var scannnedComponent4 = new ScannedComponent
            {
                LocationsFoundAt = "test".Split(),
                Component = new NpmComponent("npmpackage", "1.0.0")
            };

            var scannedComponents = new List<ScannedComponent>()
            {
                scannnedComponent1,
                scannnedComponent2,
                scannnedComponent3,
                scannnedComponent4
            };

            var componentsChannel = Channel.CreateUnbounded<ScannedComponent>();
            foreach (var component in scannedComponents)
            {
                await componentsChannel.Writer.WriteAsync(component);
            }

            componentsChannel.Writer.Complete();

            var converter = new ComponentToExternalReferenceInfoConverter(mockLogger.Object);
            var (results, errors) = converter.Convert(componentsChannel);

            var refs = await results.ReadAllAsync().ToListAsync();
            var errorList = await errors.ReadAllAsync().ToListAsync();

            Assert.IsTrue(errorList.Count == scannedComponents.Where(c => !(c.Component is SpdxComponent)).ToList().Count);
            Assert.IsTrue(refs.Count == scannedComponents.Where(c => c.Component is SpdxComponent).ToList().Count);
        }
    }
}
