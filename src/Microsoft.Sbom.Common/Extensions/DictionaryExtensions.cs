// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Common.Extensions
{
    /// <summary>
    /// Extension methods for standard <see cref="IDictionary{TKey, TValue}"/> implementations.
    /// </summary>
    public static class DictionaryExtensions
    {
        /// <summary>
        /// Adds the value to the dictionary only if the value is not null,
        /// and the if dictionary already doesn't contain the given key.
        /// </summary>
        /// <typeparam name="Tkey"></typeparam>
        /// <typeparam name="TValue"></typeparam>
        /// <param name="dictionary"></param>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void AddIfKeyNotPresentAndValueNotNull<Tkey, TValue>(
            this IDictionary<Tkey, TValue> dictionary,
            Tkey key,
            TValue value)
        {
            if (dictionary is null)
            {
                throw new ArgumentNullException(nameof(dictionary));
            }

            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            // Check if the value is not null, and if the dictionary already
            // contains a value for the key.
            if (value != null && !dictionary.ContainsKey(key))
            {
                dictionary.Add(key, value);
            }
        }
    }
}
