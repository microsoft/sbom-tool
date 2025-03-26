// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Tools.Tests;

[TestClass]
public class IntegrationTests
{
    private const string ManifestRootFolderName = "_manifest";
    private const string ManifestFileName = "manifest.spdx.json";

    private static readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    public TestContext TestContext { get; set; }

    private static string testRunDirectory;

    [ClassInitialize]
    public static void Setup(TestContext context)
    {
        testRunDirectory = context.TestRunDirectory;
    }

    [ClassCleanup(ClassCleanupBehavior.EndOfClass)]
    public static void TearDown()
    {
        // Clean up test directories
        if (testRunDirectory is not null)
        {
            if (Directory.Exists(testRunDirectory))
            {
                Directory.Delete(testRunDirectory, true);
            }
        }
    }

    [TestMethod]
    public void TargetAppExists()
    {
        Assert.IsTrue(File.Exists(GetAppName()));
    }

    [TestMethod]
    public void E2E_NoParameters_DisplaysHelpMessage_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(null);

        Assert.AreEqual(stderr, string.Empty);
        Assert.IsTrue(stdout.Contains("Validate -options"));
        Assert.IsTrue(stdout.Contains("Generate -options"));
        Assert.IsTrue(stdout.Contains("Redact -options"));
        Assert.AreNotEqual(0, exitCode.Value);
    }

    [TestMethod]
    public void E2E_GenerateManifest_GeneratesManifest_ReturnsZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);
    }

    [TestMethod]
    public void E2E_GenerateAndValidateManifest_ValidationSucceeds_ReturnsZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath);

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        Assert.AreEqual(0, exitCode.Value);
        Assert.IsTrue(File.Exists(outputFile), $"{outputFile} should have been created during validation");
        Assert.IsTrue(File.ReadAllText(outputFile).Contains("\"Result\":\"Success\"", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void E2E_GenerateAndRedactManifest_RedactedFileIsSmaller_ReturnsZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var outputFolder = Path.Combine(TestContext.TestRunDirectory, TestContext.TestName, "redacted");
        var originalManifestFolderPath = AppendFullManifestFolderPath(testFolderPath);
        var originalManifestFilePath = Path.Combine(AppendFullManifestFolderPath(testFolderPath), ManifestFileName);
        var arguments = $"redact -sp \"{originalManifestFilePath}\" -o \"{outputFolder}\" -verbosity verbose";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        Assert.AreEqual(0, exitCode.Value);
        Assert.IsTrue(stdout.Contains("Result=Success", StringComparison.OrdinalIgnoreCase));
        var redactedManifestFilePath = Path.Combine(outputFolder, ManifestFileName);
        var originalManifestSize = File.ReadAllText(originalManifestFilePath).Length;
        var redactedManifestSize = File.ReadAllText(redactedManifestFilePath).Length;
        Assert.IsTrue(redactedManifestSize > 0, "Redacted file must not be empty");
        Assert.IsTrue(redactedManifestSize < originalManifestSize, "Redacted file must be smaller than the original");
    }

    [TestMethod]
    public void E2E_GenerateAndRedactSPDX30Manifest_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoValue: "3.0");

        var outputFolder = Path.Combine(TestContext.TestRunDirectory, TestContext.TestName, "redacted");
        var originalManifestFolderPath = AppendFullManifestFolderPath(testFolderPath, spdxVersion: "3.0");
        var originalManifestFilePath = Path.Combine(originalManifestFolderPath, ManifestFileName);
        var arguments = $"redact -sp \"{originalManifestFilePath}\" -o \"{outputFolder}\" -verbosity verbose";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.IsTrue(stdout.Contains("Redaction is only supported for SPDX 2.2 currently. Please provide a valid SPDX 2.2 SBOM."), $"Unexpected output: {stdout}");
        Assert.AreEqual(1, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Generate_WithBadManifestInfo_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        var arguments = $"generate -ps IntegrationTests -pn IntegrationTests -pv 1.2.3 -m \"{testFolderPath}\" -b . -bc \"{GetSolutionFolderPath()}\" -mi randomName:randomVersion";
        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.AreEqual("Please provide a valid value for the ManifestInfo (-mi) parameter. Supported values include: SPDX:2.2, SPDX:3.0. The values are case-insensitive.\r\n", stderr);
        Assert.AreNotEqual(0, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Validate_WithBadManifestInfo_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, "randomName:randomVersion");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.AreEqual("Please provide a valid value for the ManifestInfo (-mi) parameter. Supported values include: SPDX:2.2, SPDX:3.0. The values are case-insensitive.\r\n", stderr);
        Assert.AreNotEqual(0, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Validate_WithBadComplianceStandard_SupportedManifestInfo_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoValue: "3.0");

        // Add the compliance standard
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoValue: "3.0", complianceStandardValue: "aeg12");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.IsTrue(stdout.Contains("Unknown Compliance Standard 'aeg12'. Options are NTIA"));
        Assert.AreEqual(1, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Validate_WithValidComplianceStandard_UnsupportedManifestInfo_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoValue: "2.2");

        // Add the compliance standard
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoValue: "2.2", complianceStandardValue: "NTIA");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.IsTrue(stderr.Contains("Please use SPDX >=3.0 or remove the ComplianceStandard parameter.\r\n"));
        Assert.AreNotEqual(0, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Validate_WithValidComplianceStandard_SupportedManifestInfo_StdOutContainsNTIAErrors()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoValue: "3.0");

        // Add the compliance standard
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoValue: "3.0", complianceStandardValue: "NTIA");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        // Assert that the validation failures show up
        Assert.IsTrue(stdout.Contains("Elements in the manifest that are non-compliant with NTIA . . . 1"));
        Assert.IsTrue(stdout.Contains("SPDXRef-software_Package-BBC2D465DDBC52CC6119533C2E784684B7088775E3FD28438F7E557563D03915"));
    }

    [DataRow("SPDX:2.2")]
    [DataRow("SPDX:3.0")]
    [DataRow("randomName:randomVersion")]
    [TestMethod]
    public void E2E_Redact_WithManifestInfo_ReturnsNonZeroExitCode(string manifestInfoValue)
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var outputFolder = Path.Combine(TestContext.TestRunDirectory, TestContext.TestName, "redacted");
        var originalManifestFolderPath = AppendFullManifestFolderPath(testFolderPath);
        var originalManifestFilePath = Path.Combine(AppendFullManifestFolderPath(testFolderPath), ManifestFileName);
        var arguments = $"redact -sp \"{originalManifestFilePath}\" -o \"{outputFolder}\" -verbosity verbose";
        arguments += $" -mi {manifestInfoValue}";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.IsTrue(stdout.Contains("Unexpected named argument: mi"));
        Assert.AreNotEqual(0, exitCode.Value);
    }

    private void GenerateManifestAndValidateSuccess(string testFolderPath, string manifestInfoValue = null)
    {
        var arguments = $"generate -ps IntegrationTests -pn IntegrationTests -pv 1.2.3 -m \"{testFolderPath}\"  -b . -bc \"{GetSolutionFolderPath()}\"";
        arguments += string.IsNullOrEmpty(manifestInfoValue) ? string.Empty : $" -mi SPDX:{manifestInfoValue}";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        var manifestFolderPath = AppendFullManifestFolderPath(testFolderPath, spdxVersion: manifestInfoValue);
        var jsonFilePath = Path.Combine(manifestFolderPath, ManifestFileName);
        var shaFilePath = Path.Combine(manifestFolderPath, "manifest.spdx.json.sha256");
        Assert.IsTrue(File.Exists(jsonFilePath));
        Assert.IsTrue(File.Exists(shaFilePath));

        // Check that manifestFolderPath is the only folder in the directory
        var directories = Directory.GetDirectories(Path.Combine(testFolderPath, ManifestRootFolderName));
        Assert.AreEqual(1, directories.Length, "There should be only one folder in the test directory.");
        Assert.AreEqual(manifestFolderPath, directories[0], "The only folder in the test directory should be a folder with the correct SBOM version name.");

        Assert.AreEqual(0, exitCode.Value);
    }

    private (string arguments, string outputFile) GetValidateManifestArguments(string testFolderPath, string manifestInfoValue = "2.2", string complianceStandardValue = "")
    {
        var outputFile = Path.Combine(TestContext.TestRunDirectory, TestContext.TestName, "validation.json");
        var manifestRootFolderName = Path.Combine(testFolderPath, ManifestRootFolderName);
        var arguments = $"validate -m \"{manifestRootFolderName}\" -b . -o \"{outputFile}\"";
        arguments += string.IsNullOrEmpty(manifestInfoValue) ? string.Empty : $" -mi SPDX:{manifestInfoValue}";
        arguments += string.IsNullOrEmpty(complianceStandardValue) ? string.Empty : $" -cs {complianceStandardValue}";
        return (arguments, outputFile);
    }

    private string CreateTestFolder()
    {
        var testFolderPath = Path.GetFullPath(Path.Combine(TestContext.TestRunDirectory, TestContext.TestName));
        Directory.CreateDirectory(testFolderPath);
        return testFolderPath;
    }

    private static string AppendFullManifestFolderPath(string manifestDir, string spdxVersion = null)
    {
        return Path.Combine(manifestDir, ManifestRootFolderName, $"spdx_{spdxVersion ?? "2.2"}");
    }

    private static string GetSolutionFolderPath()
    {
        return Path.GetFullPath(Path.Combine(Assembly.GetExecutingAssembly().Location, "..", "..", ".."));
    }

    private static string GetAppName()
    {
        return IsWindows ? "Microsoft.Sbom.Tool.exe" : "Microsoft.Sbom.Tool";
    }

    private static (string stdout, string stderr, int? exitCode) LaunchAndCaptureOutput(string? arguments)
    {
        var stdout = string.Empty;
        var stderr = string.Empty;
        int? exitCode = null;
        Process process = null;

        try
        {
            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = GetAppName(),
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Arguments = arguments ?? string.Empty,
                }
            };

            process.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    stdout += e.Data + Environment.NewLine;
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    stderr += e.Data + Environment.NewLine;
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.WaitForExit();
        }
        catch (Exception e)
        {
            Assert.Fail($"Caught the following Exception: {e}");
        }
        finally
        {
            if (process is not null)
            {
                if (!process.HasExited)
                {
                    process.Kill();
                }

                exitCode = process.ExitCode;
                process.Dispose();
            }
        }

        return (stdout, stderr, exitCode);
    }
}
