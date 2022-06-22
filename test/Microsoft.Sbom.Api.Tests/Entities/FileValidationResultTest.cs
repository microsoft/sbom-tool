using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Contracts.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using EntityErrorType = Microsoft.Sbom.Contracts.Enums.ErrorType;

namespace Microsoft.Sbom.Api.Tests.Entities
{
    [TestClass]
    public class FileValidationResultTest
    {
        [TestMethod]
        [DataRow(ErrorType.AdditionalFile, EntityErrorType.FileError)]
        [DataRow(ErrorType.FilteredRootPath, EntityErrorType.FileError)]
        [DataRow(ErrorType.ManifestFolder, EntityErrorType.FileError)]
        [DataRow(ErrorType.MissingFile, EntityErrorType.FileError)]
        [DataRow(ErrorType.InvalidHash, EntityErrorType.HashingError)]
        [DataRow(ErrorType.UnsupportedHashAlgorithm, EntityErrorType.HashingError)]
        [DataRow(ErrorType.JsonSerializationError, EntityErrorType.JsonSerializationError)]
        [DataRow(ErrorType.None, EntityErrorType.None)]
        [DataRow(ErrorType.PackageError, EntityErrorType.PackageError)]
        [DataRow(ErrorType.Other, EntityErrorType.Other)]
        public void FileValidationResultErrorTypeMapping(ErrorType input, EntityErrorType output)
        {
            var fileValidationResult = new FileValidationResult() { ErrorType = input, Path = "random"};
            var entityError = fileValidationResult.ToEntityError();

            Assert.AreEqual(entityError.ErrorType, output);
            Assert.AreEqual(entityError.Details, null);

            if(input == ErrorType.PackageError)
            {
                Assert.AreEqual(((PackageEntity)entityError.Entity).Path, "random");
                Assert.AreEqual(((PackageEntity)entityError.Entity).Name, "random");
                Assert.AreEqual(entityError.Entity.GetType(), typeof(PackageEntity));
            }
            else
            {
                Assert.AreEqual(((FileEntity)entityError.Entity).Path, "random");
                Assert.AreEqual(entityError.Entity.GetType(),typeof(FileEntity));
            }
        }
    }
}
