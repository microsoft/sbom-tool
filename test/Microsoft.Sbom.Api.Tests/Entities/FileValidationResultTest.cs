// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Contracts.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using EntityErrorType = Microsoft.Sbom.Contracts.Enums.ErrorType;

namespace Microsoft.Sbom.Api.Tests.Entities;

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
    public void FileValidationResultErrorTypeMapping(ErrorType input, EntityErrorType expectedOutput)
    {
        var fileValidationResult = new FileValidationResult() { ErrorType = input, Path = "random" };
        var entityError = fileValidationResult.ToEntityError();

        Assert.AreEqual(expectedOutput, entityError.ErrorType);
        Assert.IsNull(entityError.Details);

        if (input == ErrorType.PackageError)
        {
            Assert.AreEqual("random", ((PackageEntity)entityError.Entity).Path);
            Assert.AreEqual("random", ((PackageEntity)entityError.Entity).Name);
            Assert.AreEqual(entityError.Entity.GetType(), typeof(PackageEntity));
        }
        else
        {
            Assert.AreEqual("random", ((FileEntity)entityError.Entity).Path);
            Assert.AreEqual(entityError.Entity.GetType(), typeof(FileEntity));
        }
    }
}
