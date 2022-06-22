// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Newtonsoft.Json.Converters;
using Newtonsoft.Json;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using EntityErrorType = Microsoft.Sbom.Contracts.Enums.ErrorType;
using Microsoft.Sbom.Contracts.Entities;

namespace Microsoft.Sbom.Api.Entities
{
    public class FileValidationResult
    {
        /// <summary>
        /// Gets or sets the relative path of the node.
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// Gets or sets the type of error if any.
        /// </summary>
        [JsonConverter(typeof(StringEnumConverter))]
        public ErrorType ErrorType { get; set; }

        // TODO: Deprecate FileValidationResult to use EntityError
        public EntityError ToEntityError()
        {
            EntityErrorType errorType = EntityErrorType.Other;
            EntityType entityType = EntityType.Unknown;
            Entity entity = null;

            switch (ErrorType)
            {
                case ErrorType.AdditionalFile:
                case ErrorType.FilteredRootPath:
                case ErrorType.ManifestFolder:
                case ErrorType.MissingFile:
                    errorType = EntityErrorType.FileError;
                    entityType = EntityType.File;
                    break;
                case ErrorType.InvalidHash:
                case ErrorType.UnsupportedHashAlgorithm:
                    errorType = EntityErrorType.HashingError;
                    break;
                case ErrorType.JsonSerializationError:
                    errorType = EntityErrorType.JsonSerializationError;
                    break;
                case ErrorType.None:
                    errorType = EntityErrorType.None;
                    break;
                case ErrorType.PackageError:
                    errorType = EntityErrorType.PackageError;
                    entityType = EntityType.Package;
                    break;
                case ErrorType.Other:
                    errorType = EntityErrorType.Other;
                    break;
            }

            switch (entityType)
            {
                case EntityType.Unknown:
                case EntityType.File:
                    entity = new FileEntity(Path);
                    break;
                case EntityType.Package:
                    entity = new PackageEntity(Path, null, Path, null);
                    break;
            }

            return new EntityError()
            {
                ErrorType = errorType,
                Entity = entity
            };
        }
    }
}
