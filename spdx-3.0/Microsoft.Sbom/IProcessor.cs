using System.Threading.Channels;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom;
internal interface IProcessor
{
    Task ProcessAsync(ChannelWriter<Element> serializerChannel, ChannelWriter<ErrorInfo> errorsChannel);
}
