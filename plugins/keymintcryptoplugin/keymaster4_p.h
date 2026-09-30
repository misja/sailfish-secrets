/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * BSD 3-Clause License, see LICENSE.
 */

// Private wire adapter, included after the shared KeyMint value types.
// android.hardware.keymaster@4.0 uses the same key tags and error codes,
// but HIDL vectors and operation handles instead of AIDL parcelables/objects.
namespace Keymaster4 {

typedef KeyMintBinderClient::CallResult Result;
const char Service[] = "android.hardware.keymaster@4.0::IKeymasterDevice/default";
const char Interface[] = "android.hardware.keymaster@4.0::IKeymasterDevice";
enum Transaction { Generate = 6, Delete = 13, Begin = 16, Update = 17,
                   Finish = 18, Abort = 19 };

struct WireParameter {
    quint32 tag;
    quint32 padding;
    quint64 scalar;
    GBinderHidlVec blob;
};
struct WireCharacteristics {
    GBinderHidlVec software;
    GBinderHidlVec hardware;
};
struct WireAuthToken {
    quint64 challenge;
    quint64 userId;
    quint64 authenticatorId;
    quint32 authenticatorType;
    quint32 padding;
    quint64 timestamp;
    GBinderHidlVec mac;
};
struct WireVerificationToken {
    quint64 challenge;
    quint64 timestamp;
    GBinderHidlVec parameters;
    quint32 securityLevel;
    quint32 padding;
    GBinderHidlVec mac;
};
static_assert(sizeof(WireParameter) == 32, "Keymaster parameter ABI");
static_assert(offsetof(WireParameter, blob) == 16, "Keymaster blob ABI");
static_assert(sizeof(WireCharacteristics) == 32, "Keymaster characteristics ABI");
static_assert(sizeof(WireAuthToken) == 56, "Keymaster auth token ABI");
static_assert(offsetof(WireAuthToken, mac) == 40, "Keymaster auth MAC ABI");
static_assert(sizeof(WireVerificationToken) == 56, "Keymaster verification ABI");

Result malformed(const char *field = "payload")
{
    return Result(false, KmSecureHardwareCommunicationFailed,
                  QStringLiteral("Malformed HIDL Keymaster response: %1").arg(QLatin1String(field)));
}

class Call {
public:
    GBinderLocalRequest *request;
    GBinderRemoteReply *reply;
    GBinderWriter writer;
    GBinderReader reader;
    explicit Call(GBinderClient *client)
        : request(gbinder_client_new_request(client)), reply(Q_NULLPTR)
    {
        if (request) gbinder_local_request_init_writer(request, &writer);
    }
    ~Call()
    {
        if (reply) gbinder_remote_reply_unref(reply);
        if (request) gbinder_local_request_unref(request);
    }
    Result run(GBinderClient *client, quint32 code)
    {
        if (!request) return Result(false, KmUnknownError);
        int status = 0;
        reply = gbinder_client_transact_sync_reply(client, code, request, &status);
        if (!reply || status) return Result(false, KmSecureHardwareCommunicationFailed,
                QStringLiteral("HIDL Keymaster transaction failed (%1)").arg(status));
        gbinder_remote_reply_init_reader(reply, &reader);
        gint32 transport = 0, error = 0;
        if (!gbinder_reader_read_int32(&reader, &transport) || transport
                || !gbinder_reader_read_int32(&reader, &error)) return malformed();
        return Result(true, error, error ? QStringLiteral("Keymaster error %1").arg(error)
                                         : QString());
    }
private:
    Q_DISABLE_COPY(Call)
};

void setBlob(GBinderWriter *writer, GBinderHidlVec *vec, const QByteArray &bytes)
{
    vec->count = bytes.size();
    if (!bytes.isEmpty()) {
        void *data = gbinder_writer_malloc(writer, bytes.size());
        memcpy(data, bytes.constData(), bytes.size());
        vec->data.ptr = data;
    }
}

void writeChild(GBinderWriter *writer, const GBinderHidlVec &vec,
                guint index, guint offset, gsize elementSize = 1)
{
    const GBinderParent parent = { index, offset };
    gbinder_writer_append_buffer_object_with_parent(writer, vec.data.ptr,
                                                    vec.count * elementSize, &parent);
}

void writeBytes(GBinderWriter *writer, const QByteArray &bytes)
{
    GBinderHidlVec *vec = gbinder_writer_new0(writer, GBinderHidlVec);
    setBlob(writer, vec, bytes);
    const guint index = gbinder_writer_append_buffer_object(writer, vec, sizeof(*vec));
    writeChild(writer, *vec, index, 0);
}

void writeParams(GBinderWriter *writer, const QVector<Parameter> &params)
{
    GBinderHidlVec *vec = gbinder_writer_new0(writer, GBinderHidlVec);
    WireParameter *items = params.isEmpty() ? Q_NULLPTR :
            static_cast<WireParameter *>(gbinder_writer_malloc0(
                writer, params.size() * sizeof(WireParameter)));
    vec->count = params.size();
    vec->data.ptr = items;
    for (int i = 0; i < params.size(); ++i) {
        items[i].tag = params[i].tag;
        if (params[i].valueTag == ValueBlob) setBlob(writer, &items[i].blob, params[i].blob);
        else items[i].scalar = params[i].scalar;
    }
    const guint root = gbinder_writer_append_buffer_object(writer, vec, sizeof(*vec));
    const GBinderParent parent = { root, 0 };
    const guint array = gbinder_writer_append_buffer_object_with_parent(
                writer, items, vec->count * sizeof(*items), &parent);
    for (int i = 0; i < params.size(); ++i)
        writeChild(writer, items[i].blob, array,
                   i * sizeof(*items) + offsetof(WireParameter, blob));
}

WireAuthToken makeAuthToken(const HardwareAuthToken &token)
{
    WireAuthToken wire = {};
    if (token.present) {
        wire.challenge = token.challenge;
        wire.userId = token.userId;
        wire.authenticatorId = token.authenticatorId;
        // HIDL struct fields are host-order; only the signed legacy byte
        // serialization uses network-order type and timestamp.
        wire.authenticatorType = token.authenticatorType;
        wire.timestamp = token.timestamp;
    }
    return wire;
}

void writeToken(GBinderWriter *writer, const HardwareAuthToken &token)
{
    WireAuthToken *wire = gbinder_writer_new0(writer, WireAuthToken);
    *wire = makeAuthToken(token);
    if (token.present) setBlob(writer, &wire->mac, token.mac);
    const guint index = gbinder_writer_append_buffer_object(writer, wire, sizeof(*wire));
    writeChild(writer, wire->mac, index, offsetof(WireAuthToken, mac));
}

void writeEmptyVerification(GBinderWriter *writer)
{
    // A single TEE needs no cross-Keymaster verification token. An empty MAC
    // is the HIDL contract's explicit absent-token representation.
    WireVerificationToken *wire = gbinder_writer_new0(writer, WireVerificationToken);
    const guint index = gbinder_writer_append_buffer_object(writer, wire, sizeof(*wire));
    writeChild(writer, wire->parameters, index, offsetof(WireVerificationToken, parameters));
    writeChild(writer, wire->mac, index, offsetof(WireVerificationToken, mac));
}

// AOSP emits canonical null child objects without adding them to Binder's
// object-offset table. libgbinder therefore leaves these bytes unread.
struct NullBufferObject {
    quint32 type;
    quint32 flags;
    quintptr buffer;
    quintptr length;
    quintptr parent;
    quintptr parentOffset;
};
static_assert(sizeof(NullBufferObject) == 8 + 4 * sizeof(quintptr), "Binder buffer ABI");

bool isNullChild(const void *data, gsize size, quintptr parentOffset)
{
    if (!data || size < sizeof(NullBufferObject)) return false;
    NullBufferObject object;
    memcpy(&object, data, sizeof(object));
    const quint32 pointerType = (quint32('p') << 24) | (quint32('t') << 16)
            | (quint32('*') << 8) | 0x85;
    // parent is an object-table index, never dereferenced here. Its value
    // varies with preceding nonempty vectors; the field offset must match.
    return object.type == pointerType && object.flags == 1
            && !object.buffer && !object.length && object.parentOffset == parentOffset;
}

bool consumeNullChild(GBinderReader *reader, quintptr parentOffset)
{
    gsize size = 0;
    const char *data = static_cast<const char *>(gbinder_reader_get_data(reader, &size));
    const gsize offset = gbinder_reader_bytes_read(reader);
    if (offset > size || !isNullChild(data ? data + offset : Q_NULLPTR,
                                    size - offset, parentOffset)) return false;
    GBinderReader probe = *reader;
    for (guint i = 0; i < sizeof(NullBufferObject) / sizeof(guint32); ++i) {
        guint32 ignored;
        if (!gbinder_reader_read_uint32(&probe, &ignored)) return false;
    }
    *reader = probe;
    return true;
}

bool readChild(GBinderReader *reader, const GBinderHidlVec &vec,
               gsize elementSize, guint maximum, const void **data, quintptr parentOffset = 0)
{
    if (vec.count > maximum) return false;
    if (!vec.data.ptr) {
        if (vec.count) return false;
        // Some HIDL peers omit a null child, others write an explicit empty
        // buffer object. Probe without consuming the following nonempty child.
        GBinderReader probe = *reader;
        GBinderBuffer *empty = gbinder_reader_read_buffer(&probe);
        if (empty && !empty->size && !empty->data) *reader = probe;
        else if (!empty) {
            // Indexed null objects may have advanced the reader already.
            if (gbinder_reader_bytes_read(&probe) != gbinder_reader_bytes_read(reader))
                *reader = probe;
            else
                consumeNullChild(reader, parentOffset);
        }
        if (empty) gbinder_buffer_free(empty);
        *data = Q_NULLPTR;
        return true;
    }
    GBinderBuffer *buffer = gbinder_reader_read_buffer(reader);
    const bool valid = buffer
            ? buffer->size == vec.count * elementSize && buffer->data == vec.data.ptr
            : !vec.count && !vec.data.ptr;
    *data = valid && buffer ? buffer->data : Q_NULLPTR;
    if (buffer) gbinder_buffer_free(buffer);
    return valid;
}

bool readBytes(GBinderReader *reader, QByteArray *bytes)
{
    const GBinderHidlVec *vec = gbinder_reader_read_hidl_struct(reader, GBinderHidlVec);
    const void *data = Q_NULLPTR;
    if (!vec || !readChild(reader, *vec, 1, MaximumBlobSize, &data)) return false;
    *bytes = QByteArray(static_cast<const char *>(data), vec->count);
    return true;
}

bool readParamChild(GBinderReader *reader, const GBinderHidlVec &vec,
                    QVector<Parameter> *params, QString *diagnostic = Q_NULLPTR,
                    quintptr parentOffset = 0)
{
    const void *data = Q_NULLPTR;
    if (!readChild(reader, vec, sizeof(WireParameter), MaximumParameters, &data, parentOffset)) {
        if (diagnostic) *diagnostic = QStringLiteral("parameter array (%1 entries)").arg(vec.count);
        return false;
    }
    const WireParameter *items = static_cast<const WireParameter *>(data);
    QVector<Parameter> parsed;
    for (guint i = 0; i < vec.count; ++i) {
        const void *blob = Q_NULLPTR;
        if (!readChild(reader, items[i].blob, 1, MaximumBlobSize, &blob,
                       i * sizeof(WireParameter) + offsetof(WireParameter, blob))) {
            if (diagnostic) *diagnostic = QStringLiteral("blob at index %1, tag %2, size %3")
                    .arg(i).arg(items[i].tag, 0, 16).arg(items[i].blob.count);
            return false;
        }
        const quint32 type = items[i].tag & 0xf0000000U;
        quint64 scalar = items[i].scalar;
        if (canonicalType(items[i].tag) == 1) scalar &= 0xff;
        else if (canonicalType(items[i].tag) == 2) scalar &= 0xffffffffU;
        Parameter parameter = (type == 0x90000000U || type == 0x80000000U)
                ? blobParameter(items[i].tag, QByteArray(
                    static_cast<const char *>(blob), items[i].blob.count))
                : scalarParameter(items[i].tag, scalar);
        if (parameter.valueTag == ValueInvalid) {
            if (diagnostic) *diagnostic = QStringLiteral("unsupported tag %1 at index %2")
                    .arg(items[i].tag, 0, 16).arg(i);
            return false;
        }
        parsed.append(parameter);
    }
    *params = parsed;
    return true;
}

bool readParams(GBinderReader *reader, QVector<Parameter> *params)
{
    const GBinderHidlVec *vec = gbinder_reader_read_hidl_struct(reader, GBinderHidlVec);
    return vec && readParamChild(reader, *vec, params);
}

Result deleteKey(GBinderClient *client, const QByteArray &blob);

Result generate(GBinderClient *client, const QVector<Parameter> &params, KeyCreation *creation)
{
    Call call(client);
    if (!call.request) return Result(false, KmUnknownError);
    writeParams(&call.writer, params);
    Result result = call.run(client, Generate);
    if (result.succeeded()) {
        KeyCreation parsed;
        if (!readBytes(&call.reader, &parsed.key.rawBlob) || parsed.key.rawBlob.isEmpty())
            return malformed("generated key blob");
        // A successful HAL generation can still yield malformed characteristics.
        // Retire only the just-created key before returning that parsing failure.
        const auto fail = [&](const QString &field) {
            deleteKey(client, parsed.key.rawBlob);
            return Result(false, KmSecureHardwareCommunicationFailed,
                          QStringLiteral("Malformed HIDL Keymaster response: %1").arg(field));
        };
        const WireCharacteristics *c = gbinder_reader_read_hidl_struct(
                    &call.reader, WireCharacteristics);
        if (!c) return fail(QStringLiteral("characteristics struct"));
        QString detail;
        if (!readParamChild(&call.reader, c->software, &parsed.characteristics.software, &detail))
            return fail(QStringLiteral("software characteristics: %1").arg(detail));
        if (!readParamChild(&call.reader, c->hardware, &parsed.characteristics.hardware, &detail,
                            offsetof(WireCharacteristics, hardware)))
            return fail(QStringLiteral("hardware characteristics: %1").arg(detail));
        if (!gbinder_reader_at_end(&call.reader)) return fail(QStringLiteral("trailing characteristics"));
        *creation = parsed;
    }
    return result;
}

Result deleteKey(GBinderClient *client, const QByteArray &blob)
{
    Call call(client);
    if (!call.request) return Result(false, KmUnknownError);
    writeBytes(&call.writer, blob);
    Result result = call.run(client, Delete);
    return result.succeeded() && !gbinder_reader_at_end(&call.reader) ? malformed() : result;
}

Result begin(GBinderClient *client, qint32 purpose, const QByteArray &blob,
             const QVector<Parameter> &params, const HardwareAuthToken &token,
             quint64 *handle, QVector<Parameter> *output)
{
    Call call(client);
    if (!call.request) return Result(false, KmUnknownError);
    gbinder_writer_append_int32(&call.writer, purpose);
    writeBytes(&call.writer, blob);
    writeParams(&call.writer, params);
    writeToken(&call.writer, token);
    Result result = call.run(client, Begin);
    guint64 parsedHandle = 0;
    if (result.succeeded()) {
        if (!readParams(&call.reader, output)
                || !gbinder_reader_read_uint64(&call.reader, &parsedHandle)
                || !parsedHandle || !gbinder_reader_at_end(&call.reader)) return malformed();
        *handle = parsedHandle;
    }
    return result;
}

Result operate(GBinderClient *client, quint64 handle, bool finish,
               const QVector<Parameter> &params, const QByteArray &input,
               const QByteArray &signature, const HardwareAuthToken &token,
               QByteArray *output)
{
    Call call(client);
    if (!call.request) return Result(false, KmUnknownError);
    gbinder_writer_append_int64(&call.writer, static_cast<gint64>(handle));
    writeParams(&call.writer, params);
    writeBytes(&call.writer, input);
    if (finish) writeBytes(&call.writer, signature);
    writeToken(&call.writer, token);
    writeEmptyVerification(&call.writer);
    Result result = call.run(client, finish ? Finish : Update);
    if (result.succeeded()) {
        guint32 consumed = 0;
        QVector<Parameter> outputParams;
        if ((!finish && (!gbinder_reader_read_uint32(&call.reader, &consumed)
                         || consumed != static_cast<guint32>(input.size())))
                || !readParams(&call.reader, &outputParams)
                || !readBytes(&call.reader, output)
                || !gbinder_reader_at_end(&call.reader)) return malformed();
    }
    return result;
}

Result abort(GBinderClient *client, quint64 handle)
{
    Call call(client);
    if (!call.request) return Result(false, KmUnknownError);
    gbinder_writer_append_int64(&call.writer, static_cast<gint64>(handle));
    Result result = call.run(client, Abort);
    return result.succeeded() && !gbinder_reader_at_end(&call.reader) ? malformed() : result;
}

} // namespace Keymaster4
