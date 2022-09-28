// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Microsoft.Sbom.Common
{
    public class WindowsFileSystemUtils : FileSystemUtils
    {
        override public bool DirectoryHasReadPermissions(string directoryPath) => DirectoryHasRights(directoryPath, FileSystemRights.Read);

        override public bool DirectoryHasWritePermissions(string directoryPath) => DirectoryHasRights(directoryPath, FileSystemRights.Write);

        // Get the collection of authorization rules that apply to the directory
        private bool DirectoryHasRights(string directoryPath, FileSystemRights fileSystemRights)
        {
            try
            {   
                WindowsIdentity current = WindowsIdentity.GetCurrent();
                var directoryInfo = new DirectoryInfo(directoryPath);

                return HasAccessControlType(AccessControlType.Allow) && !HasAccessControlType(AccessControlType.Deny);
                
                // Check if the current user has or does not have the specified rights (either Allow or Deny)
                bool HasAccessControlType(AccessControlType accessControlType)
                { 
                    var accessRules = directoryInfo.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
                    .Cast<FileSystemAccessRule>()
                    .Any(rule => (current.Groups.Contains(rule.IdentityReference) || current.User.Equals(rule.IdentityReference))
                        && ((fileSystemRights & rule.FileSystemRights) == fileSystemRights)
                        && (rule.AccessControlType == accessControlType));
                    return accessRules;
                }
            }
            catch (Exception)
            {
                // TODO Add logger with debug
                return false;
            }
        }
    }
}
