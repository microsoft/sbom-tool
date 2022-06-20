using System;
using System.Collections;

namespace Microsoft.Sbom.Common
{
    /// <summary>
    /// Wrapper class for System.Environment to allow for testing
    /// </summary>
    public class EnvironmentWrapper : IEnvironmentWrapper
    {
        /// <summary>
        /// Method to call System.Environment.GetEnvironmentVariables.
        /// </summary>
        /// <returns> A dictionary of available environment variables. </returns>
        public IDictionary GetEnvironmentVariables()
        {
            return Environment.GetEnvironmentVariables();
        }
    }
}
