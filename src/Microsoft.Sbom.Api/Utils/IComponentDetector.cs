using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Api.Utils;

public interface IComponentDetector
{
    Task<ScanResult> ScanAsync(string[] args);
}