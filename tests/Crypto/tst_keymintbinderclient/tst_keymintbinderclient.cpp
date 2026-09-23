/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "../../../plugins/keymintcryptoplugin/keymintbinderclient.cpp"

#include <QtTest/QtTest>

class tst_keymintbinderclient : public QObject
{
    Q_OBJECT

private slots:
    void capabilityPayloadIsStrict();
    void authSetRoundTripAndPolicy();
    void authenticationIdentityPolicy();
    void opaqueKeyAndEnvelopeRoundTrip();
    void hardwareAuthTokenParsing();
    void hidlTokenLayout();
    void hidlNullChildEncoding();
    void hidlKeymasterSmoke_data();
    void hidlKeymasterSmoke();
    void attestationFailsClosed();
    void legacyCertificateValidity();
};

void tst_keymintbinderclient::capabilityPayloadIsStrict()
{
    const qint32 supportedLevels[] = {
        SecurityLevelSoftware,
        SecurityLevelTrustedEnvironment,
        SecurityLevelStrongBox
    };
    for (qint32 securityLevel : supportedLevels) {
        const QByteArray response = serializeCapabilitiesResponse(securityLevel);
        QCOMPARE(response.size(), 8);
        Cursor cursor(response);
        quint32 version = 0;
        quint32 parsedSecurityLevel = 100;
        QVERIFY(cursor.take(&version));
        QVERIFY(cursor.take(&parsedSecurityLevel));
        QVERIFY(cursor.atEnd());
        QCOMPARE(version, ProtocolVersion);
        QCOMPARE(parsedSecurityLevel, quint32(securityLevel));
    }

    QVERIFY(serializeCapabilitiesResponse(-1).isEmpty());
    QVERIFY(serializeCapabilitiesResponse(100).isEmpty());
}

void tst_keymintbinderclient::authSetRoundTripAndPolicy()
{
    const quint64 secureUserId = 0x123456789abcdef0ULL;
    QVector<Parameter> parameters;
    parameters << scalarParameter(TagUserSecureId, secureUserId)
               << scalarParameter(TagUserAuthType, AuthenticatorPassword)
               << scalarParameter(TagAuthTimeout, 30)
               << blobParameter(TagAssociatedData, QByteArray("aad"));

    const QByteArray serialized = serializeAuthSet(parameters);
    QVERIFY(!serialized.isEmpty());

    QVector<Parameter> parsed;
    QVERIFY(parseAuthSet(serialized, &parsed));
    QCOMPARE(parsed.size(), parameters.size());
    QCOMPARE(parsed.at(0).tag, TagUserSecureId);
    QCOMPARE(parsed.at(0).valueTag, qint32(ValueLongInteger));
    QCOMPARE(parsed.at(0).scalar, secureUserId);
    QCOMPARE(parsed.at(3).tag, TagAssociatedData);
    QCOMPARE(parsed.at(3).valueTag, qint32(ValueBlob));
    QCOMPARE(parsed.at(3).blob, QByteArray("aad"));

    QVERIFY(policyMatchesIdentity(parsed, secureUserId, 0));
    QVERIFY(!policyMatchesIdentity(parsed, secureUserId + 1, 0));

    QVector<Parameter> noAuthentication;
    noAuthentication << scalarParameter(TagNoAuthRequired, 1);
    QVERIFY(policyMatchesIdentity(noAuthentication, secureUserId + 1, 0));

    QByteArray truncated = serialized;
    truncated.chop(1);
    QVERIFY(!parseAuthSet(truncated, &parsed));

    QByteArray wrongType = serialized;
    const quint32 type = qToLittleEndian(quint32(2));
    wrongType.replace(12, sizeof(type),
                      reinterpret_cast<const char *>(&type), sizeof(type));
    QVERIFY(!parseAuthSet(wrongType, &parsed));

    QByteArray trailing = serialized;
    trailing.append('\0');
    QVERIFY(!parseAuthSet(trailing, &parsed));
}

void tst_keymintbinderclient::authenticationIdentityPolicy()
{
    const quint64 secureUserId = Q_UINT64_C(0x1020304050607080);
    const quint64 fingerprintAuthenticatorId
            = Q_UINT64_C(0x2122232425262728);

    QVector<Parameter> biometric;
    biometric << scalarParameter(TagUserSecureId,
                                 fingerprintAuthenticatorId)
              << scalarParameter(TagUserAuthType,
                                 AuthenticatorFingerprint);
    QVERIFY(policyMatchesIdentity(biometric, secureUserId,
                                  fingerprintAuthenticatorId));
    QVERIFY(!policyMatchesIdentity(biometric, secureUserId,
                                   fingerprintAuthenticatorId + 1));

    QVector<Parameter> wrongType = biometric;
    wrongType[1] = scalarParameter(TagUserAuthType, AuthenticatorPassword);
    QVERIFY(!policyMatchesIdentity(wrongType, secureUserId,
                                   fingerprintAuthenticatorId));

    QVector<Parameter> mixed = biometric;
    mixed << scalarParameter(TagUserSecureId,
                             fingerprintAuthenticatorId + 1);
    QVERIFY(!policyMatchesIdentity(mixed, secureUserId,
                                   fingerprintAuthenticatorId));

    QVector<Parameter> rootFingerprint;
    rootFingerprint << scalarParameter(TagUserSecureId, secureUserId)
                    << scalarParameter(TagUserAuthType,
                                       AuthenticatorFingerprint);
    QVERIFY(policyMatchesIdentity(rootFingerprint, secureUserId,
                                  fingerprintAuthenticatorId));

    HardwareAuthToken token;
    token.present = true;
    token.userId = secureUserId;
    token.authenticatorType = AuthenticatorPassword;
    QVERIFY(tokenMatchesIdentity(token, secureUserId,
                                 fingerprintAuthenticatorId));
    token.authenticatorId = fingerprintAuthenticatorId;
    QVERIFY(!tokenMatchesIdentity(token, secureUserId,
                                  fingerprintAuthenticatorId));

    token.authenticatorType = AuthenticatorFingerprint;
    QVERIFY(tokenMatchesIdentity(token, secureUserId,
                                 fingerprintAuthenticatorId));
    QVERIFY(!tokenMatchesIdentity(token, secureUserId,
                                  fingerprintAuthenticatorId + 1));
    ++token.userId;
    QVERIFY(!tokenMatchesIdentity(token, secureUserId,
                                  fingerprintAuthenticatorId));
}

void tst_keymintbinderclient::opaqueKeyAndEnvelopeRoundTrip()
{
    OpaqueKey key;
    key.rawBlob = QByteArray::fromHex("010203040506");
    key.certificates << QByteArray("certificate-one")
                     << QByteArray("certificate-two");
    key.publicKey = QByteArray("public-key");

    const QByteArray serializedKey = serializeOpaqueKey(key);
    QVERIFY(!serializedKey.isEmpty());

    OpaqueKey parsedKey;
    QVERIFY(parseOpaqueKey(serializedKey, &parsedKey));
    QCOMPARE(parsedKey.rawBlob, key.rawBlob);
    QCOMPARE(parsedKey.certificates, key.certificates);
    QCOMPARE(parsedKey.publicKey, key.publicKey);

    QByteArray trailingKey = serializedKey;
    trailingKey.append('\0');
    QVERIFY(!parseOpaqueKey(trailingKey, &parsedKey));

    OpaqueKey legacyKey;
    QVERIFY(parseOpaqueKey(QByteArray("legacy-keymint-blob"), &legacyKey));
    QCOMPARE(legacyKey.rawBlob, QByteArray("legacy-keymint-blob"));

    KeyMintEnvelope envelope;
    envelope.sailfishUserId = 100000;
    envelope.secureUserId = 0x1122334455667788ULL;
    envelope.identityEpoch = QByteArray(IdentityEpochSize, '\x42');
    envelope.backendVersion = BackendVersion;
    envelope.keyBlob = serializedKey;
    envelope.nonce = QByteArray(GcmNonceSize, '\x24');
    envelope.ciphertext = QByteArray(RootKeySize, '\x55');
    envelope.authenticationTag = QByteArray(GcmTagSize, '\x66');

    const QByteArray serializedEnvelope = serializeEnvelope(envelope);
    QVERIFY(!serializedEnvelope.isEmpty());

    KeyMintEnvelope parsedEnvelope;
    QVERIFY(parseEnvelope(serializedEnvelope, &parsedEnvelope));
    QCOMPARE(parsedEnvelope.sailfishUserId, envelope.sailfishUserId);
    QCOMPARE(parsedEnvelope.secureUserId, envelope.secureUserId);
    QCOMPARE(parsedEnvelope.identityEpoch, envelope.identityEpoch);
    QCOMPARE(parsedEnvelope.backendVersion, envelope.backendVersion);
    QCOMPARE(parsedEnvelope.keyBlob, envelope.keyBlob);
    QCOMPARE(parsedEnvelope.nonce, envelope.nonce);
    QCOMPARE(parsedEnvelope.ciphertext, envelope.ciphertext);
    QCOMPARE(parsedEnvelope.authenticationTag, envelope.authenticationTag);
    QCOMPARE(authenticatedEnvelopeData(parsedEnvelope),
             authenticatedEnvelopeData(envelope));

    QByteArray trailingEnvelope = serializedEnvelope;
    trailingEnvelope.append('\0');
    QVERIFY(!parseEnvelope(trailingEnvelope, &parsedEnvelope));

    QByteArray wrongMagic = serializedEnvelope;
    wrongMagic[0] = 'X';
    QVERIFY(!parseEnvelope(wrongMagic, &parsedEnvelope));
}

void tst_keymintbinderclient::hardwareAuthTokenParsing()
{
    const quint64 challenge = 0x0102030405060708ULL;
    const quint64 secureUserId = 0x1112131415161718ULL;
    const quint64 authenticatorId = 0x2122232425262728ULL;
    const quint64 timestamp = 0x3132333435363738ULL;
    QByteArray mac(32, '\0');
    mac[31] = '\x7f';

    QByteArray masterToken;
    appendLittleEndian(&masterToken, quint32(1));
    appendLittleEndian(&masterToken, challenge);
    appendLittleEndian(&masterToken, secureUserId);
    appendLittleEndian(&masterToken, authenticatorId);
    appendLittleEndian(&masterToken, quint32(AuthenticatorPassword));
    appendLittleEndian(&masterToken, timestamp);
    masterToken.append(mac);

    HardwareAuthToken parsedMaster;
    QVERIFY(parseMasterHardwareAuthToken(masterToken, &parsedMaster));
    QVERIFY(parsedMaster.present);
    QCOMPARE(parsedMaster.challenge, challenge);
    QCOMPARE(parsedMaster.userId, secureUserId);
    QCOMPARE(parsedMaster.timestamp, timestamp);
    QCOMPARE(parsedMaster.mac, mac);

    QByteArray zeroMacMaster = masterToken;
    zeroMacMaster.replace(zeroMacMaster.size() - 32, 32, QByteArray(32, '\0'));
    QVERIFY(parseMasterHardwareAuthToken(zeroMacMaster, &parsedMaster));
    QCOMPARE(parsedMaster.mac, QByteArray(32, '\0'));

    QByteArray zeroTimestampMaster = masterToken;
    const quint64 zero = 0;
    zeroTimestampMaster.replace(32, sizeof(zero),
                                reinterpret_cast<const char *>(&zero), sizeof(zero));
    QVERIFY(!parseMasterHardwareAuthToken(zeroTimestampMaster, &parsedMaster));

    QByteArray appToken;
    appendLittleEndian(&appToken, quint32(1));
    appendLittleEndian(&appToken, quint32(1));
    appendLittleEndian(&appToken, challenge);
    appendLittleEndian(&appToken, secureUserId);
    appendLittleEndian(&appToken, authenticatorId);
    appendLittleEndian(&appToken, quint32(2));
    appendLittleEndian(&appToken, timestamp);
    appendBlob(&appToken, mac);

    Cursor cursor(appToken);
    HardwareAuthToken parsedApp;
    QVERIFY(parseAppHardwareAuthToken(&cursor, &parsedApp));
    QVERIFY(cursor.atEnd());
    QVERIFY(parsedApp.present);
    QCOMPARE(parsedApp.authenticatorType, quint32(2));
    QCOMPARE(parsedApp.mac, mac);

    QByteArray zeroMacApp = appToken;
    zeroMacApp.replace(zeroMacApp.size() - 32, 32, QByteArray(32, '\0'));
    Cursor zeroMacCursor(zeroMacApp);
    QVERIFY(parseAppHardwareAuthToken(&zeroMacCursor, &parsedApp));
    QVERIFY(zeroMacCursor.atEnd());
    QCOMPARE(parsedApp.mac, QByteArray(32, '\0'));

    QByteArray absentToken;
    appendLittleEndian(&absentToken, quint32(0));
    Cursor absentCursor(absentToken);
    QVERIFY(parseAppHardwareAuthToken(&absentCursor, &parsedApp));
    QVERIFY(absentCursor.atEnd());
    QVERIFY(!parsedApp.present);

    QVERIFY(emptyVerificationToken(QByteArray()));
    QVERIFY(!emptyVerificationToken(QByteArray("malformed")));

    QByteArray verificationToken;
    appendLittleEndian(&verificationToken, quint32(1));
    appendLittleEndian(&verificationToken, quint64(0));
    appendLittleEndian(&verificationToken, quint64(0));
    appendLittleEndian(&verificationToken, quint32(0));
    appendBlob(&verificationToken,
               serializeAuthSet(QVector<Parameter>()));
    appendBlob(&verificationToken, QByteArray());
    QVERIFY(emptyVerificationToken(verificationToken));

    QByteArray hardwareVerificationToken = verificationToken;
    const quint32 hardwareSecurityLevel = qToLittleEndian(quint32(1));
    hardwareVerificationToken.replace(
                sizeof(quint32) + 2 * sizeof(quint64),
                sizeof(hardwareSecurityLevel),
                reinterpret_cast<const char *>(&hardwareSecurityLevel),
                sizeof(hardwareSecurityLevel));
    QVERIFY(!emptyVerificationToken(hardwareVerificationToken));
}

void tst_keymintbinderclient::attestationFailsClosed()
{
    KeyMintBinderClient client;
    QByteArray response("stale-certificate-chain");
    const KeyMintBinderClient::CallResult result = client.oneShot(
                AttestOperation, QByteArray("request-is-not-forwarded"), &response);
    QVERIFY(result.transportSucceeded);
    QCOMPARE(result.keyMintError, qint32(KmUnimplemented));
    QVERIFY(!result.succeeded());
    QVERIFY(response.isEmpty());
}

void tst_keymintbinderclient::legacyCertificateValidity()
{
    for (quint32 algorithm : {1U, 3U}) {
        QVector<Parameter> parameters;
        parameters << scalarParameter(TagAlgorithm, algorithm);
        addLegacyCertificateValidity(&parameters);
        QCOMPARE(parameters.size(), 3);
        QCOMPARE(parameters.at(1).tag, TagCertificateNotBefore);
        QCOMPARE(parameters.at(1).valueTag, qint32(ValueDateTime));
        QCOMPARE(parameters.at(1).scalar, quint64(0));
        QCOMPARE(parameters.at(2).tag, TagCertificateNotAfter);
        QCOMPARE(parameters.at(2).valueTag, qint32(ValueDateTime));
        QCOMPARE(parameters.at(2).scalar, Q_UINT64_C(253402300799000));

        // Existing dates survive unchanged, and a second pass adds nothing.
        parameters[1].scalar = 1234;
        parameters[2].scalar = 5678;
        const QByteArray original = serializeAuthSet(parameters);
        addLegacyCertificateValidity(&parameters);
        QCOMPARE(serializeAuthSet(parameters), original);

        parameters.removeLast();
        addLegacyCertificateValidity(&parameters);
        QCOMPARE(parameters.at(1).scalar, quint64(1234));
        QCOMPARE(parameters.at(2).scalar, Q_UINT64_C(253402300799000));

        parameters.remove(1);
        addLegacyCertificateValidity(&parameters);
        QCOMPARE(parameters.at(1).tag, TagCertificateNotAfter);
        QCOMPARE(parameters.at(2).tag, TagCertificateNotBefore);
        QCOMPARE(parameters.at(2).scalar, quint64(0));
    }
    for (quint32 algorithm : {32U, 33U, 128U}) { // AES, 3DES, HMAC
        QVector<Parameter> parameters;
        parameters << scalarParameter(TagAlgorithm, algorithm);
        const QByteArray original = serializeAuthSet(parameters);
        addLegacyCertificateValidity(&parameters);
        QCOMPARE(serializeAuthSet(parameters), original);
    }
    QVector<Parameter> empty;
    addLegacyCertificateValidity(&empty);
    QVERIFY(empty.isEmpty());
}

void tst_keymintbinderclient::hidlTokenLayout()
{
    HardwareAuthToken token;
    token.present = true;
    token.challenge = Q_UINT64_C(0x1020304050607080);
    token.userId = 123;
    token.authenticatorId = 456;
    token.authenticatorType = AuthenticatorPassword;
    token.timestamp = Q_UINT64_C(0x1122334455667788);
    const Keymaster4::WireAuthToken wire = Keymaster4::makeAuthToken(token);
    QCOMPARE(wire.challenge, token.challenge);
    QCOMPARE(wire.userId, token.userId);
    QCOMPARE(wire.authenticatorId, token.authenticatorId);
    QCOMPARE(wire.authenticatorType, token.authenticatorType);
    QCOMPARE(wire.timestamp, token.timestamp);
    QCOMPARE(wire.padding, quint32(0));
    token.present = false;
    const Keymaster4::WireAuthToken empty = Keymaster4::makeAuthToken(token);
    QCOMPARE(empty.challenge, quint64(0));
    QCOMPARE(empty.timestamp, quint64(0));
    QCOMPARE(empty.mac.count, guint32(0));
}

void tst_keymintbinderclient::hidlNullChildEncoding()
{
    Keymaster4::NullBufferObject object = {};
    object.type = (quint32('p') << 24) | (quint32('t') << 16) | (quint32('*') << 8) | 0x85;
    object.flags = 1;
    object.parent = 3;
    object.parentOffset = 16;
    QVERIFY(Keymaster4::isNullChild(&object, sizeof(object), 16));
    QVERIFY(!Keymaster4::isNullChild(&object, sizeof(object) - 1, 16));
    QVERIFY(!Keymaster4::isNullChild(&object, sizeof(object), 0));
    object.length = 1;
    QVERIFY(!Keymaster4::isNullChild(&object, sizeof(object), 16));
    object.length = 0;
    object.buffer = 1;
    QVERIFY(!Keymaster4::isNullChild(&object, sizeof(object), 16));
    object.buffer = 0;
    object.flags = 0;
    QVERIFY(!Keymaster4::isNullChild(&object, sizeof(object), 16));
    object.flags = 1;
    object.type = 0;
    QVERIFY(!Keymaster4::isNullChild(&object, sizeof(object), 16));
}

void tst_keymintbinderclient::hidlKeymasterSmoke_data()
{
    QTest::addColumn<int>("authenticationType");
    QTest::newRow("password") << int(AuthenticatorPassword);
    QTest::newRow("fingerprint") << int(AuthenticatorFingerprint);
    QTest::newRow("password-or-fingerprint") << int(AuthenticatorPassword | AuthenticatorFingerprint);
    QTest::newRow("no-auth-scratch-control") << 0;
}

void tst_keymintbinderclient::hidlKeymasterSmoke()
{
    if (qgetenv("SAILFISH_TEST_KEYMASTER4") != "1")
        QSKIP("Explicit device opt-in required; creates and deletes one scratch key");
    GBinderServiceManager *manager = gbinder_servicemanager_new("/dev/hwbinder");
    QVERIFY(manager);
    GBinderRemoteObject *remote = gbinder_servicemanager_get_service_sync(
                manager, Keymaster4::Service, Q_NULLPTR);
    GBinderClient *client = remote ? gbinder_client_new(remote, Keymaster4::Interface) : Q_NULLPTR;
    if (!client) {
        gbinder_servicemanager_unref(manager);
        QFAIL("No HIDL Keymaster 4.0 service");
    }
    QFETCH(int, authenticationType);
    quint64 testSecureId = Q_UINT64_C(0x1020304050607080);
    const QByteArray handlePath = qgetenv("SAILFISH_TEST_KEYMASTER_SID_HANDLE");
    if (!handlePath.isEmpty()) {
        // Optional real-SID control. Read only the public-format version/SID
        // prefix on the device; never print/export it or read the credential MAC.
        QFile handleFile(QString::fromLocal8Bit(handlePath));
        QVERIFY(handleFile.open(QIODevice::ReadOnly));
        const QByteArray prefix = handleFile.read(9);
        QVERIFY(handleFile.size() == 58 && prefix.size() == 9 && quint8(prefix[0]) <= 2);
        memcpy(&testSecureId, prefix.constData() + 1, sizeof(testSecureId));
        QVERIFY(testSecureId != 0);
    }
    QVector<Parameter> params;
    params << scalarParameter(TagPurpose, PurposeEncrypt)
           << scalarParameter(TagPurpose, PurposeDecrypt)
           << scalarParameter(TagAlgorithm, AlgorithmAes)
           << scalarParameter(TagKeySize, 256)
           << scalarParameter(TagBlockMode, BlockModeGcm)
           << scalarParameter(TagPadding, PaddingNone)
           << scalarParameter(TagMinMacLength, 128);
    if (authenticationType) {
        params << scalarParameter(TagUserSecureId, testSecureId)
               << scalarParameter(TagUserAuthType, authenticationType);
    } else {
        // Transport control only: never used for the production master key.
        params << scalarParameter(TagNoAuthRequired, 1);
    }
    KeyCreation creation;
    const Keymaster4::Result generated = Keymaster4::generate(client, params, &creation);
    Keymaster4::Result begun, aborted, removed;
    bool secureIdEnforced = false, authTypeEnforced = false, timeoutPresent = false;
    for (const Parameter &parameter : creation.characteristics.hardware) {
        if (parameter.tag == TagUserSecureId)
            secureIdEnforced |= parameter.scalar == testSecureId;
        if (parameter.tag == TagUserAuthType)
            authTypeEnforced |= parameter.scalar == quint64(authenticationType);
        timeoutPresent |= parameter.tag == TagAuthTimeout;
    }
    for (const Parameter &parameter : creation.characteristics.software)
        timeoutPresent |= parameter.tag == TagAuthTimeout;
    bool scratchRoundTrip = authenticationType != 0;
    quint64 handle = 0;
    QVector<Parameter> out;
    if (generated.succeeded()) {
        QVector<Parameter> operationParams;
        operationParams << scalarParameter(TagBlockMode, BlockModeGcm)
                        << scalarParameter(TagPadding, PaddingNone)
                        << scalarParameter(TagMacLength, 128);
        begun = Keymaster4::begin(client, PurposeEncrypt, creation.key.rawBlob,
                                  operationParams, HardwareAuthToken(), &handle, &out);
        if (handle) aborted = Keymaster4::abort(client, handle);
        if (!authenticationType && begun.succeeded()) {
            QByteArray nonce, encrypted, decrypted;
            const QByteArray plaintext(32, '\x42');
            const auto crypt = [&](qint32 purpose, const QByteArray &input, QByteArray *output) {
                QVector<Parameter> cryptParams = operationParams;
                if (purpose == PurposeDecrypt) cryptParams << blobParameter(TagNonce, nonce);
                QVector<Parameter> returned;
                quint64 operationHandle = 0;
                Keymaster4::Result result = Keymaster4::begin(client, purpose, creation.key.rawBlob,
                            cryptParams, HardwareAuthToken(), &operationHandle, &returned);
                if (!result.succeeded()) return false;
                if (purpose == PurposeEncrypt) nonce = nonceFromParameters(returned);
                QVector<Parameter> aad;
                aad << blobParameter(TagAssociatedData, QByteArray("scratch-test-aad"));
                QByteArray ignored;
                result = Keymaster4::operate(client, operationHandle, false, aad, QByteArray(),
                                            QByteArray(), HardwareAuthToken(), &ignored);
                if (!result.succeeded()) {
                    Keymaster4::abort(client, operationHandle);
                    return false;
                }
                result = Keymaster4::operate(client, operationHandle, true, QVector<Parameter>(),
                                            input, QByteArray(), HardwareAuthToken(), output);
                return result.succeeded();
            };
            scratchRoundTrip = crypt(PurposeEncrypt, plaintext, &encrypted)
                    && crypt(PurposeDecrypt, encrypted, &decrypted) && decrypted == plaintext;
        }
        removed = Keymaster4::deleteKey(client, creation.key.rawBlob);
    }
    gbinder_client_unref(client);
    gbinder_servicemanager_unref(manager);
    QVERIFY2(generated.succeeded(), qPrintable(generated.errorMessage));
    QVERIFY2(removed.succeeded(), qPrintable(removed.errorMessage));
    if (authenticationType) {
        QVERIFY(secureIdEnforced);
        QVERIFY(authTypeEnforced);
        QVERIFY(!timeoutPresent);
    }
    QVERIFY2(begun.succeeded(), qPrintable(begun.errorMessage));
    QVERIFY2(aborted.succeeded(), qPrintable(aborted.errorMessage));
    QCOMPARE(nonceFromParameters(out).size(), GcmNonceSize);
    QVERIFY(scratchRoundTrip);
}

QTEST_APPLESS_MAIN(tst_keymintbinderclient)

#include "tst_keymintbinderclient.moc"
