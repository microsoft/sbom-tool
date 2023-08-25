using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Api.Executors;
public interface ILicenseInformationFetcher
{
    List<string> ConvertComponentsToListForApi(IEnumerable<ScannedComponent> scannedComponents);

    Task<List<HttpResponseMessage>> FetchLicenseInformationAsync(List<string> listOfComponentsForApi);

    ConcurrentDictionary<string, string> GetLicenseDictionary();

    Task<Dictionary<string, string>> ConvertClearlyDefinedApiResponseToList(HttpResponseMessage httpResponse);

    void AppendLicensesToDictionary(Dictionary<string, string> partialLicenseDictionary);

    public string GetFromLicenseDictionary(string key);
}
