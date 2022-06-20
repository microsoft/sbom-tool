using System;

namespace Microsoft.Sbom.Common.Utils
{
    /// <summary>
    /// Provides utility function to create short Guids.
    /// </summary>
    public static class IdentifierUtils
    {
        public static string GetShortGuid(Guid guid)
        {
            var base64Guid = Convert.ToBase64String(guid.ToByteArray());

            // Replace URL unfriendly characters with better ones
            base64Guid = base64Guid.Replace('+', '-').Replace('/', '_');

            // Remove the trailing ==
            return base64Guid[0..^2];
        }

        public static bool TryGetGuidFromShortGuid(string str, out Guid guid)
        {
            if (string.IsNullOrWhiteSpace(str))
            {
                guid = Guid.Empty;
                return false;
            }

            try
            {
                str = str.Replace('_', '/').Replace('-', '+');
                var byteArray = Convert.FromBase64String(str + "==");
                guid = new Guid(byteArray);
                return true;
            }
            catch (Exception)
            {
                guid = Guid.Empty;
                return false;
            }
        }
    }
}
