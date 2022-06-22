// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Contracts.Enums;
using PowerArgs;
using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Config
{
    public class ArgRevivers
    {
        /// <summary>
        /// Creates a list of <see cref="ManifestInfo"/> objects from a string value
        /// The string manifest infos are seperated by commas.
        /// </summary>
        [ArgReviver]
        public static IList<ManifestInfo> ReviveManifestInfo(string _, string value)
        {
            try
            {
                IList<ManifestInfo> manifestInfos = new List<ManifestInfo>();
                string[] values = value.Split(',');
                foreach (var manifestInfoStr in values)
                {
                    manifestInfos.Add(ManifestInfo.Parse(manifestInfoStr));
                }

                return manifestInfos;
            }
            catch (Exception e)
            {
                throw new ValidationArgException($"Unable to parse manifest info string list: {value}. Error: {e.Message}");
            }
        }

        /// <summary>
        /// Creates an <see cref="AlgorithmName"/> object from a string value.
        /// </summary>
        [ArgReviver]
        public static AlgorithmName ReviveAlgorithmName(string _, string value)
        {
            try
            {
                // Return a placeholder object for now. The config post processor will convert this into
                // a real AlgorithmName object. We only need to preserve the string value (name) of the algorithm.
                return new AlgorithmName(value, null);
            }
            catch (Exception e)
            {
                throw new ValidationArgException($"Unable to parse algorithm name: {value}. Error: {e.Message}");
            }
        }
    }
}
