// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using Serilog;

/// <summary>
/// Wrapper around file system functions. Used for unit testing.
/// Windows implementation.
/// </summary>
[SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "This is a Windows only implementation")]
public class WindowsFileSystemUtils : FileSystemUtils
{
    private readonly ILogger logger;

    /// <summary>
    /// Constructor for <see cref="WindowsFileSystemUtils"/>.
    /// </summary>
    /// <param name="logger">Logger to capture any exceptions</param>
    /// <exception cref="ArgumentNullException"></exception>
    public WindowsFileSystemUtils(ILogger logger)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public override bool DirectoryHasReadPermissions(string directoryPath) => this.DirectoryHasRights(directoryPath, FileSystemRights.Read);

    /// <inheritdoc />
    public override bool DirectoryHasWritePermissions(string directoryPath) =>
        this.DirectoryHasRights(directoryPath, FileSystemRights.Write);

    /// <summary>
    /// Get the collection of authorization rules that apply to the directory.
    /// </summary>
    /// <returns>True if the directory has the specified rights, false otherwise.</returns>
    private bool DirectoryHasRights(string directoryPath, FileSystemRights fileSystemRights)
    {
        try
        {
            var current = WindowsIdentity.GetCurrent();
            var directoryInfo = new DirectoryInfo(directoryPath);

            return HasAccessControlType(AccessControlType.Allow) && !HasAccessControlType(AccessControlType.Deny);

            // Check if the current user has or does not have the specified rights (either Allow or Deny)
            bool HasAccessControlType(AccessControlType accessControlType)
            {
                var accessRules = directoryInfo.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
                    .Cast<FileSystemAccessRule>()
                    .Any(
                        rule => (current.Groups.Contains(rule.IdentityReference) || current.User.Equals(rule.IdentityReference))
                                && (fileSystemRights & rule.FileSystemRights) == fileSystemRights
                                && rule.AccessControlType == accessControlType);
                return accessRules;
            }
        }
        catch (Exception e)
        {
            logger.Warning("Unable to obtain directory rights. Exception = {Exception}", e);
            return false;
        }
    }
}
