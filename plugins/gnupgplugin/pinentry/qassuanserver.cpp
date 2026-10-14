/*
 * Copyright (C) 2016 Caliste Damien.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "qassuanserver.h"

#include <Secrets/storesecretrequest.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/interactionrequest.h>
#include <Secrets/createcollectionrequest.h>

#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishPinentry, "org.sailfishos.secrets.gnupg.pinentry", QtWarningMsg)

const QString QAssuanServer::Temporary = QStringLiteral("Temporary");


#if PINENTRY_MODERN_ASSUAN
gpg_error_t _reset_handler(assuan_context_t ctx, char *line)
#else
void _reset_handler(assuan_context_t ctx)
#endif
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    self->cacheId.setName(QString());
    self->prompt = Sailfish::Secrets::InteractionParameters::PromptText();
#if PINENTRY_MODERN_ASSUAN
    Q_UNUSED(line);
    return 0;
#endif
}

PinentryAssuanError _option_handler(assuan_context_t ctx, const char *key, const char *value)
{
    qCDebug(lcSailfishPinentry) << __func__ << key << value;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    if (!strcmp(key, "no-grab") && !*value) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_SUPPORTED);
    } else if (!strcmp(key, "grab") && !*value) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "debug-wait")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "display")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "ttyname")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "ttytype")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "lc-ctype")) {
        self->m_ctype = value;
    } else if (!strcmp(key, "lc-messages")) {
        self->m_messages = value;
    } else if (!strcmp(key, "parent-wid")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "touch-file")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "default-ok")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "default-cancel")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "default-prompt")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "default-pwmngr")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "allow-external-password-cache") && !*value) {
        self->m_externalCacheAllowed = true;
        return 0;
    } else if (!strcmp(key, "invisible-char")) {
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NOT_IMPLEMENTED);
    } else
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_UNKNOWN_OPTION);
    return 0;
}

PinentryAssuanError _assuan_cmd_setdesc(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setMessage(QByteArray::fromPercentEncoding(line).simplified());

    // Ugly hack here due to GnuPG being stuck in 2.0.4
    // and not having SETKEYINFO command yet. Description looks like:
    // "user: "John Dow <john.dow@example.org>""
    // "2048-bit RSA key, ID A099539B, created 2018-04-13 (main key ID 41123AA4)"
    {
        const QString &str(self->prompt.message());
        int id = str.lastIndexOf(", ID ");
        if (id > 0) {
            self->cacheId.setName(str.mid(id + 5, 8));
            qCDebug(lcSailfishPinentry) << "cacheID" << self->cacheId.name();
        }
    }
    return 0;
}

PinentryAssuanError _assuan_cmd_setprompt(assuan_context_t ctx, char *line)
{
    Q_UNUSED(ctx);
    qCDebug(lcSailfishPinentry) << __func__ << line;

    //QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    //self->m_prompt = QByteArray::fromPercentEncoding(line);
    return 0;
}

PinentryAssuanError _assuan_cmd_seterror(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setInstruction(QByteArray::fromPercentEncoding(line));
    return 0;
}

PinentryAssuanError _assuan_cmd_setrepeat(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->cacheId.setName(QString());

    return 0;
}

PinentryAssuanError _assuan_cmd_setok(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setAccept(QByteArray::fromPercentEncoding(line));

    return 0;
}

PinentryAssuanError _assuan_cmd_setcancel(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setCancel(QByteArray::fromPercentEncoding(line));

    return 0;
}

/* The data provided at LINE may be used by pinentry implementations
   to identify a key for caching strategies of its own.  The empty
   string and --clear mean that the key does not have a stable
   identifier.  */
PinentryAssuanError _assuan_cmd_setkeyinfo(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->cacheId.setName((*line && strcmp(line, "--clear") !=0) ? line : QString());

    return 0;
}

PinentryAssuanError _assuan_cmd_getpassphrase(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    QByteArray passphrase;
    bool fromCache = false;
    Sailfish::Secrets::Result result = self->requestPassphrase(&passphrase, fromCache);
    if (result.errorCode() == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
        qCWarning(lcSailfishPinentry) << "cancelation" << result.errorMessage();
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_CANCELED);
    }
    if (result.code() != Sailfish::Secrets::Result::Succeeded) {
        qCWarning(lcSailfishPinentry) << result.errorMessage();
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_GENERAL);
    }

    gpg_error_t rc = 0;
    if (fromCache) {
        rc = assuan_write_status(self->m_ctx, "PASSWORD_FROM_CACHE", "");
    }
    if (!rc) {
        rc = assuan_send_data(self->m_ctx, passphrase.constData(), passphrase.length());
    }
    if (!rc) {
        rc = assuan_send_data(self->m_ctx, NULL, 0);
    }

    return rc;
}

PinentryAssuanError _assuan_cmd_confirm(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    Sailfish::Secrets::Result result = self->requestConfirmation();
    if (result.errorCode() == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
      return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_CANCELED);
    }
    if (result.code() != Sailfish::Secrets::Result::Succeeded) {
        qCWarning(lcSailfishPinentry) << result.errorMessage();
        return gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_GENERAL);
    }
    return 0;
}

#define PACKAGE_VERSION "0.0.1"
/* GETINFO <what>

   Multipurpose function to return a variety of information.
   Supported values for WHAT are:

     version     - Return the version of the program.
     pid         - Return the process id of the server.
 */
static PinentryAssuanError _assuan_cmd_getinfo(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    int rc = 0;
    if (!strcmp(line, "version")) {
        const char *s = PACKAGE_VERSION;
        rc = assuan_send_data (ctx, s, strlen (s));
    } else if (!strcmp(line, "pid")) {
        char numbuf[50];

        snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
        rc = assuan_send_data(ctx, numbuf, strlen (numbuf));
    } else {
        rc = gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_INV_VALUE);
    }
    return rc;
}

PinentryAssuanError _assuan_cmd_stop(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    // assuan_set_flag(ctx, ASSUAN_FORCE_CLOSE, 1);
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->m_request_stop = true;

    return 0;
}

/* Tell the assuan library about our commands.  */
static gpg_error_t register_commands(assuan_context_t ctx)
{
  static struct
  {
    const char *name;
    PinentryCommandHandler handler;
  } table[] =
    {
      { "SETDESC",        _assuan_cmd_setdesc },
      { "SETPROMPT",      _assuan_cmd_setprompt },
      { "SETERROR",       _assuan_cmd_seterror },
      { "SETKEYINFO",     _assuan_cmd_setkeyinfo }, // Not yet present in 2.0.4
      { "SETREPEAT",      _assuan_cmd_setrepeat },  // Not yet present in 2.0.4
      { "SETOK",          _assuan_cmd_setok },
      { "SETCANCEL",      _assuan_cmd_setcancel },
      { "GETPIN",         _assuan_cmd_getpassphrase },
      { "CONFIRM",        _assuan_cmd_confirm },
      { "GETINFO",        _assuan_cmd_getinfo },
      { "STOP",           _assuan_cmd_stop },
      { NULL, NULL }
    };
  int i, j;
  gpg_error_t rc;

  for (i = j = 0; table[i].name; i++) {
      rc = pinentryAssuanRegister(ctx, table[i].name, table[i].handler);
      if (rc)
          return rc;
  }
  return 0;
}

QAssuanServer::QAssuanServer(QObject *parent)
    : QThread(parent)
    , secretManager()
    , m_useCache(new MDConfItem("/desktop/sailfish/secrets/storeGnuPGPassphrases", this))
    , m_connected(false)
    , m_ctx(0)
    , m_request_stop(false)
    , m_externalCacheAllowed(false)
{
    gpg_error_t rc;
    int filedesc[2];

    filedesc[0] = 0;
    filedesc[1] = 1;
    rc = pinentryAssuanInit(&m_ctx, filedesc);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to initialize the server: " << gpg_strerror(rc);
        pinentryAssuanRelease(m_ctx);
        m_ctx = 0;
        return;
    }
    rc = register_commands(m_ctx);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register commands with Assuan: " << gpg_strerror(rc);
        pinentryAssuanRelease(m_ctx);
        m_ctx = 0;
        return;
    }

    assuan_set_pointer(m_ctx, this);
    rc = assuan_register_option_handler(m_ctx, _option_handler);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register option handler with Assuan: " << gpg_strerror(rc);
        pinentryAssuanRelease(m_ctx);
        m_ctx = 0;
        return;
    }
    rc = assuan_register_reset_notify(m_ctx, _reset_handler);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register reset handler with Assuan: " << gpg_strerror(rc);
        pinentryAssuanRelease(m_ctx);
        m_ctx = 0;
        return;
    }

    cacheId.setCollectionName(QStringLiteral("GnuPG"));
    cacheId.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    m_connected = true;
}

QAssuanServer::~QAssuanServer()
{
    if (isRunning()) {
        terminate();
        wait(500);
    }
    if (m_ctx) {
        pinentryAssuanRelease(m_ctx);
        m_ctx = 0;
    }
}

bool QAssuanServer::start()
{
    if (!m_connected) {
        return false;
    }

    QThread::start();
    return true;
}

void QAssuanServer::run()
{
    PinentryAssuanError rc;

    for (;;) {
        rc = assuan_accept(m_ctx);
        if (rc == static_cast<PinentryAssuanError>(-1))
            break;
        else if (rc) {
            qCWarning(lcSailfishPinentry) << "Assuan accept failed: " << pinentryAssuanStrerror(rc);
            break;
        }

        rc = assuan_process(m_ctx);
        if (rc) {
            qCWarning(lcSailfishPinentry) << "Assuan processing failed: " << pinentryAssuanStrerror(rc);
            continue;
        }

        if (m_request_stop) {
            break;
        }
    }
    qCDebug(lcSailfishPinentry) << "Assuan loop finished.";
}

Sailfish::Secrets::Result QAssuanServer::requestPassphrase(QByteArray *passphrase, bool &fromCache)
{
    passphrase->clear();
    fromCache = false;

    bool useCache = m_externalCacheAllowed && m_useCache->value(QVariant(true)).toBool();
    if (useCache && cacheId.isValid() && prompt.instruction().isEmpty()) {
        Sailfish::Secrets::StoredSecretRequest request;
        qCDebug(lcSailfishPinentry) << "Starting cache request for" << cacheId.name();
        request.setManager(&secretManager);
        request.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        request.setIdentifier(cacheId);
        request.startRequest();
        request.waitForFinished();
        qCDebug(lcSailfishPinentry) << "-> return code" << request.result().code();
        qCDebug(lcSailfishPinentry) << request.result().errorMessage();
        if (request.result().code() == Sailfish::Secrets::Result::Succeeded) {
            qCDebug(lcSailfishPinentry) << "found cached secret";
            *passphrase = request.secret().data();
            fromCache = true;
            return request.result();
        } else if (request.result().code() == Sailfish::Secrets::Result::Failed
                   && request.result().errorCode() == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            // Later on, in case of a valid key, don't ask again the
            // user to grant access to key caching.
            useCache = false;
        }
    }

    Sailfish::Secrets::InteractionParameters uiParams;
    uiParams.setPromptText(prompt);
    uiParams.setInputType(Sailfish::Secrets::InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(Sailfish::Secrets::InteractionParameters::PasswordEcho);

    Sailfish::Secrets::InteractionRequest request;
    request.setInteractionParameters(uiParams);
    request.setManager(&secretManager);

    qCDebug(lcSailfishPinentry) << "Starting passphrase request";
    request.startRequest();
    request.waitForFinished();
    qCDebug(lcSailfishPinentry) << "-> return code" << request.result().code();
    if (request.result().code() == Sailfish::Secrets::Result::Succeeded) {
        *passphrase = request.userInput();
        if (useCache && cacheId.isValid() && ensureCacheCollection()) {
            Sailfish::Secrets::StoreSecretRequest store;
            // store.setInteractionParameters(uiParams);

            store.setManager(&secretManager);
            store.setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
            store.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);

            Sailfish::Secrets::Secret pin(cacheId);
            pin.setType(Sailfish::Secrets::Secret::TypeBlob);
            pin.setData(request.userInput());
            store.setSecret(pin);

            qCDebug(lcSailfishPinentry) << "Storing passphrase for" << cacheId.name();
            store.startRequest();
            store.waitForFinished();
            qCDebug(lcSailfishPinentry) << "-> return code" << store.result().code();
            if (store.result().code() != Sailfish::Secrets::Result::Succeeded)
                qCWarning(lcSailfishPinentry) << store.result().errorMessage();
        }
    }

    return request.result();
}

Sailfish::Secrets::Result QAssuanServer::requestConfirmation()
{
    Sailfish::Secrets::InteractionParameters uiParams;
    uiParams.setPromptText(prompt);
    uiParams.setInputType(Sailfish::Secrets::InteractionParameters::ConfirmationInput);

    Sailfish::Secrets::InteractionRequest request;
    request.setInteractionParameters(uiParams);

    request.setManager(&secretManager);

    qCDebug(lcSailfishPinentry) << "Starting confirmation request";
    request.startRequest();
    request.waitForFinished();
    qCDebug(lcSailfishPinentry) << "-> return code" << request.result().code();
    return request.result();
}

bool QAssuanServer::ensureCacheCollection()
{
    // Ensure collection exists.
    Sailfish::Secrets::CreateCollectionRequest request;
    request.setManager(&secretManager);
    request.setCollectionName(cacheId.collectionName());
    request.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    request.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    request.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    request.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.setEncryptionPluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed
        && request.result().errorCode() != Sailfish::Secrets::Result::CollectionAlreadyExistsError) {
        qCWarning(lcSailfishPinentry) << "Ensuring collection failed:" << request.result().errorMessage();
        return false;
    }
    return true;
}
