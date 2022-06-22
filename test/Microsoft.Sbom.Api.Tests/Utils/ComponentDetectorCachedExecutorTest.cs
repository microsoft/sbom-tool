using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Tests.Utils
{
    [TestClass]
    public class ComponentDetectorCachedExecutorTest
    {
        private readonly Mock<ILogger> logger = new Mock<ILogger>();
        private readonly Mock<ComponentDetector> detector = new Mock<ComponentDetector>();

        [TestInitialize]
        public void TestInitialize()
        {
            logger.Reset();
            detector.Reset();
        }

        [TestMethod]
        public void Scan()
        {
            var executor = new ComponentDetectorCachedExecutor(logger.Object, detector.Object);
            var arguments = new string[] { "a", "b", "c" };
            var expectedResult = new ScanResult();

            detector.Setup(x => x.Scan(arguments)).Returns(expectedResult);
            var result = executor.Scan(arguments);
            Assert.AreEqual(result, expectedResult);
            Assert.IsTrue(detector.Invocations.Count == 1);
        }

        [TestMethod]
        public void ScanWithCache()
        {
            var executor = new ComponentDetectorCachedExecutor(logger.Object, detector.Object);
            var arguments = new string[] { "a", "b", "c" };
            var expectedResult = new ScanResult();

            detector.Setup(x => x.Scan(arguments)).Returns(expectedResult);
            executor.Scan(arguments);
            var result = executor.Scan(arguments);
            Assert.AreEqual(result, expectedResult);
            Assert.IsTrue(detector.Invocations.Count == 1);
        }
    }
}
