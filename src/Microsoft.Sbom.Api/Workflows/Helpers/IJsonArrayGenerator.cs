﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Output;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;

namespace Microsoft.Sbom.Api.Workflows.Helpers
{
    /// <summary>
    /// Used to generate array objects in the JSON serializer.
    /// </summary>
    public interface IJsonArrayGenerator
    {
        /// <summary>
        /// Generates an array in the json serializer with the headerName and writes all elements of the 
        /// specific type into the array.
        /// </summary>
        /// <returns>The list of failures.</returns>
        Task<IList<FileValidationResult>> GenerateAsync();
    }
}
