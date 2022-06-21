﻿using Microsoft.Sbom.Adapters.Adapters.ComponentDetection;
using Microsoft.Sbom.Adapters.Report;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System;
using System.Linq;
using Microsoft.Sbom.Contracts;
using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Adapters
{
    public class ComponentDetectionToSBOMPackageAdapter
    {
        /// <summary>
        /// Parses the output from Component Detection and converts it into a list of <see cref="SBOMPackage"/> objects.
        /// The report returned by this function will also indicate any errors encountered by the adapter, and on successful
        /// runs a success log entry will be added.
        /// </summary>
        /// <param name="bcdeOutputPath">Path to the 'bcde-output.json' file.</param>
        /// <returns>A report generated by the adapter, and a list of <see cref="SBOMPackage"/> objects.</returns>
        /// <exception cref="ArgumentNullException">When the bcdeOutputPath parameter is not valid.</exception>
        public (AdapterReport, IEnumerable<SBOMPackage>) TryConvert(string bcdeOutputPath)
        {
            if (string.IsNullOrWhiteSpace(bcdeOutputPath) || !File.Exists(bcdeOutputPath))
            {
                throw new ArgumentNullException(nameof(bcdeOutputPath));
            }

            var report = new AdapterReport();
            IEnumerable<SBOMPackage> packages = new List<SBOMPackage>(); // returns an empty list of packages if there are no components or an error occurs.

            try
            {
                ScanResult? componentDetectionScanResult = JsonConvert.DeserializeObject<ScanResult>(File.ReadAllText(bcdeOutputPath));

                if (componentDetectionScanResult == null)
                {
                    report.LogFailure($"Parsing bcde-output.json at '{bcdeOutputPath}' returns null.");
                }
                else if (componentDetectionScanResult.ComponentsFound != null)
                {
                    packages = componentDetectionScanResult.ComponentsFound
                        .Select(component => component.ToSbomPackage(report))
                        // It is acceptable to return a partial list of values with null filtered out since they should be reported as failures already
                        .Where(package => package != null)
                        .Select(package => package!);

                    report.LogSuccess();
                }
                else
                {
                    // Log success if no components were found as well
                    report.LogSuccess();
                }
            }
            catch (Exception ex)
            {
                report.LogFailure($"Unable to parse bcde-output.json at path '{bcdeOutputPath}' due to the following exception: {ex}");
            }

            return (report, packages);
        }
    }
}