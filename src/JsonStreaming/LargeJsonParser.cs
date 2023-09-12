// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace JsonStreaming;

public class LargeJsonParser
{
    private const int DefaultReadBufferSize = 4096;
    private readonly Stream stream;
    private readonly IReadOnlyDictionary<string, PropertyHandler> handlers;
    private readonly JsonSerializerOptions jsonSerializerOptions;
    private byte[] buffer;
    private JsonReaderState readerState;
    private bool isFinalBlock;
    private bool isParsingStarted = false;
    private bool arrayFinishing = false;

    public LargeJsonParser(
        Stream stream,
        IReadOnlyDictionary<string, PropertyHandler> handlers,
        JsonSerializerOptions? jsonSerializerOptions = default,
        int bufferSize = DefaultReadBufferSize)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
        this.handlers = handlers ?? throw new ArgumentNullException(nameof(handlers));
        this.jsonSerializerOptions = jsonSerializerOptions ?? new JsonSerializerOptions()
        {
        };

        this.buffer = new byte[bufferSize];

        // Validate buffer is not of 0 length.
        if (buffer.Length == 0)
        {
            throw new ArgumentException($"The {nameof(this.buffer)} value can't be null or of 0 length.");
        }

        this.stream.Position = GetStartPosition(this.stream);

        if (!stream.CanRead || stream.Read(this.buffer) == 0)
        {
            throw new EndOfStreamException();
        }

        static int GetStartPosition(Stream stream)
        {
            var bom = Encoding.UTF8.Preamble.ToArray();
            stream.Position = 0;
            var buffer = new byte[bom.Length];
            _ = stream.Read(buffer, 0, buffer.Length);

            return Enumerable.SequenceEqual(buffer, bom) ? 3 : 0;
        }
    }

    /// <summary>
    /// Begin evaluating the next section of the json stream.
    /// </summary>
    /// <returns>A ParserStateResult object describing the section that was encountered or null if this was the final state.</returns>
    /// <remarks>If the result object is an enumerable you MUST ensure that you've walked it entirely before calling next again.</remarks>
    public ParserStateResult? Next()
    {
        if (this.handlers is null)
        {
            throw new InvalidOperationException("Handlers must be initialized before calling Next.");
        }

        try
        {
            var reader = new Utf8JsonReader(this.buffer, isFinalBlock: this.isFinalBlock, this.readerState);

            if (!this.isParsingStarted)
            {
                ParserUtils.SkipNoneTokens(this.stream, ref this.buffer, ref reader);

                ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.StartObject);
                ParserUtils.GetMoreBytesFromStream(this.stream, ref this.buffer, ref reader);

                this.isParsingStarted = true;
            }

            // Eat the previous token.
            ParserUtils.Read(this.stream, ref this.buffer, ref reader);

            // If the end of the Json Object is reached, return null to indicate completion.
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return null;
            }

            ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.PropertyName);
            var propertyName = reader.GetString() ?? throw new NotImplementedException();

            ParserUtils.Read(this.stream, ref buffer, ref reader);
            ParserStateResult resultState;
            if (this.handlers.ContainsKey(propertyName))
            {
                resultState = this.HandleExplicitProperty(ref reader, propertyName);
            }
            else
            {
                resultState = this.HandleExtraProperty(ref reader, propertyName);
            }

            ParserUtils.GetMoreBytesFromStream(this.stream, ref this.buffer, ref reader);

            // If the end of the Json Object is reached, return null to indicate completion.
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return null;
            }

            this.isFinalBlock = reader.IsFinalBlock;
            this.readerState = reader.CurrentState;

            return resultState;
        }
        catch (JsonException ex)
        {
            throw new ParserException($"Error parsing json at position {this.stream.Position}", ex);
        }
    }

    private ParserStateResult HandleExplicitProperty(ref Utf8JsonReader reader, string propertyName)
    {
        var handler = this.handlers![propertyName];

        object? result;
        switch (handler.Type)
        {
            case ParameterType.String:
                ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.String);
                result = reader.GetString();
                break;
            case ParameterType.Skip:
                ParserUtils.SkipProperty(this.stream, ref this.buffer, ref reader);
                result = null;
                break;
            case ParameterType.Int:
                ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.Number);
                var i = reader.GetInt32();
                result = i;
                break;
            case ParameterType.Object:
                ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.StartObject);
                var objType = handler.GetType().GetGenericArguments()[0];
                var obj = this.GetObject(objType, ref reader);
                result = obj;
                break;
            case ParameterType.Array:
                ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.StartArray);
                var aryType = handler.GetType().GetGenericArguments()[0];
                result = this.GetArray(aryType);
                break;
            default:
                throw new InvalidOperationException($"Unknown {nameof(ParameterType)}: {handler.Type}");
        }

        return new ParserStateResult(propertyName, result);
    }

    private ParserStateResult HandleExtraProperty(ref Utf8JsonReader reader, string propertyName)
    {
        var result = reader.TokenType switch
        {
            JsonTokenType.String => reader.GetString(),
            JsonTokenType.Number => reader.GetInt32(),
            JsonTokenType.StartArray => throw new NotImplementedException(),
            JsonTokenType.StartObject => throw new NotImplementedException(),
            JsonTokenType.True => true,
            JsonTokenType.False => (object)false,
            JsonTokenType.None => throw new NotImplementedException(),
            JsonTokenType.EndObject => throw new NotImplementedException(),
            JsonTokenType.EndArray => throw new NotImplementedException(),
            JsonTokenType.PropertyName => throw new NotImplementedException(),
            JsonTokenType.Comment => throw new NotImplementedException(),
            JsonTokenType.Null => throw new NotImplementedException(),
            _ => throw new InvalidOperationException($"Unknown {nameof(JsonTokenType)}: {reader.TokenType}"),
        };
        return new ParserStateResult(propertyName, result);
    }

    private IEnumerable<object> GetArray(Type type)
    {
        while (true)
        {
            var obj = this.ReadArrayObject(type);
            if (obj is not null)
            {
                yield return obj;
            }
            else
            {
                yield break;
            }
        }
    }

    private object GetObject(Type type, ref Utf8JsonReader reader)
    {
        var jsonObject = this.ReadObject(ref reader);
        var result = jsonObject.Deserialize(type, this.jsonSerializerOptions);

        if (result is null)
        {
            throw new NotImplementedException();
        }

        return result;
    }

    private object? ReadArrayObject(Type type)
    {
        try
        {
            if (this.arrayFinishing)
            {
                this.arrayFinishing = false;
                return null;
            }

            var reader = new Utf8JsonReader(this.buffer, this.isFinalBlock, this.readerState);

            if (reader.TokenType == JsonTokenType.StartArray)
            {
                ParserUtils.SkipFirstArrayToken(this.stream, ref this.buffer, ref reader);
            }

            object? result;
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                result = null;
            }
            else
            {
                result = this.GetObject(type, ref reader);
            }

            if (reader.TokenType == JsonTokenType.EndArray)
            {
                this.arrayFinishing = true;
            }

            ParserUtils.GetMoreBytesFromStream(this.stream, ref this.buffer, ref reader);

            this.isFinalBlock = reader.IsFinalBlock;
            this.readerState = reader.CurrentState;

            return result;
        }
        catch (JsonException ex)
        {
            throw new ParserException($"Error parsing json at position {this.stream.Position}", ex);
        }
    }

    private JsonNode ReadObject(ref Utf8JsonReader reader)
    {
        ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.StartObject);
        var obj = JsonNode.Parse(ref reader) ?? throw new NotImplementedException();
        ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.EndObject);
        ParserUtils.Read(this.stream, ref this.buffer, ref reader);
        return obj;
    }
}
