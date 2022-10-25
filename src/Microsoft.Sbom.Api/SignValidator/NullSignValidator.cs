using Microsoft.Sbom.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.SignValidator
{
    public class NullSignValidator : ISignValidator
    {
        public OSPlatform SupportedPlatform => OSPlatform.Windows;

        public bool Validate()
        {
            return true;
        }
    }
}
