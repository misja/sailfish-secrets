/*
 * Copyright (C) 2016 Caliste Damien.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "qassuanserver.h"

#include <Secrets/interactionrequest.h>

#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishPinentry, "org.sailfishos.secrets.gnupg.pinentry", QtWarningMsg)

const QString QAssuanServer::Temporary = QStringLiteral("Temporary");

// To be removed when upgrading libassuan to a modern version using gpg-error.
typedef gpg_error_t (*OptionHandler)(assuan_context_t, const char*, const char*);
typedef gpg_error_t (*CmdHandler)(assuan_context_t, char *);

gpg_error_t _reset_handler(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    Q_UNUSED(line);
    self->prompt = Sailfish::Secrets::InteractionParameters::PromptText();
    return 0;
}

gpg_error_t _option_handler(assuan_context_t ctx, const char *key, const char *value)
{
    qCDebug(lcSailfishPinentry) << __func__ << key;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    if (!strcmp(key, "no-grab") && !*value) {
        return gpg_error(GPG_ERR_NOT_SUPPORTED);
    } else if (!strcmp(key, "grab") && !*value) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "debug-wait")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "display")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "ttyname")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "ttytype")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "lc-ctype")) {
        self->m_ctype = value;
    } else if (!strcmp(key, "lc-messages")) {
        self->m_messages = value;
    } else if (!strcmp(key, "parent-wid")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "touch-file")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "default-ok")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "default-cancel")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "default-prompt")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "default-pwmngr")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else if (!strcmp(key, "allow-external-password-cache") && !*value) {
        return 0; // Persistence is unconditionally disabled in this build.
    } else if (!strcmp(key, "invisible-char")) {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    } else
        return gpg_error(GPG_ERR_UNKNOWN_OPTION);
    return 0;
}

gpg_error_t _assuan_cmd_setdesc(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setMessage(QByteArray::fromPercentEncoding(line).simplified());

    return 0;
}

gpg_error_t _assuan_cmd_setprompt(assuan_context_t ctx, char *line)
{
    Q_UNUSED(ctx);
    qCDebug(lcSailfishPinentry) << __func__;

    //QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    //self->m_prompt = QByteArray::fromPercentEncoding(line);
    return 0;
}

gpg_error_t _assuan_cmd_seterror(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setInstruction(QByteArray::fromPercentEncoding(line));
    return 0;
}

gpg_error_t _assuan_cmd_setrepeat(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    return 0;
}

gpg_error_t _assuan_cmd_setok(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setAccept(QByteArray::fromPercentEncoding(line));

    return 0;
}

gpg_error_t _assuan_cmd_setcancel(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setCancel(QByteArray::fromPercentEncoding(line));

    return 0;
}

/* The data provided at LINE may be used by pinentry implementations
   to identify a key for caching strategies of its own.  The empty
   string and --clear mean that the key does not have a stable
   identifier.  */
gpg_error_t _assuan_cmd_setkeyinfo(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    Q_UNUSED(self); Q_UNUSED(line); // No external cache in this UI-only proof.

    return 0;
}

gpg_error_t _assuan_cmd_getpassphrase(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    QByteArray passphrase;
    Sailfish::Secrets::Result result = self->requestPassphrase(&passphrase);
    if (result.errorCode() == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
        qCWarning(lcSailfishPinentry) << "cancelation" << result.errorCode();
        return gpg_error(GPG_ERR_CANCELED);
    }
    if (result.code() != Sailfish::Secrets::Result::Succeeded) {
        qCWarning(lcSailfishPinentry) << result.errorCode();
        return gpg_error(GPG_ERR_GENERAL);
    }

    gpg_error_t rc = assuan_send_data(self->m_ctx, passphrase.constData(), passphrase.length());
    if (!rc) {
        rc = assuan_send_data(self->m_ctx, NULL, 0);
    }

    return rc;
}

gpg_error_t _assuan_cmd_confirm(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    Sailfish::Secrets::Result result = self->requestConfirmation();
    if (result.errorCode() == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
      return gpg_error(GPG_ERR_CANCELED);
    }
    if (result.code() != Sailfish::Secrets::Result::Succeeded) {
        qCWarning(lcSailfishPinentry) << result.errorCode();
        return gpg_error(GPG_ERR_GENERAL);
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
static gpg_error_t _assuan_cmd_getinfo(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
    int rc = 0;
    if (!strcmp(line, "version")) {
        const char *s = PACKAGE_VERSION;
        rc = assuan_send_data (ctx, s, strlen (s));
    } else if (!strcmp(line, "pid")) {
        char numbuf[50];

        snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
        rc = assuan_send_data(ctx, numbuf, strlen (numbuf));
    } else {
        rc = gpg_error(GPG_ERR_INV_VALUE);
    }
    return rc;
}

gpg_error_t _assuan_cmd_stop(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__;
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
    gpg_error_t (*handler) (assuan_context_t, char *line);
  } table[] =
    {
      { "SETDESC",        (CmdHandler)_assuan_cmd_setdesc },
      { "SETPROMPT",      (CmdHandler)_assuan_cmd_setprompt },
      { "SETERROR",       (CmdHandler)_assuan_cmd_seterror },
      { "SETKEYINFO",     (CmdHandler)_assuan_cmd_setkeyinfo }, // Not yet present in 2.0.4
      { "SETREPEAT",      (CmdHandler)_assuan_cmd_setrepeat },  // Not yet present in 2.0.4
      { "SETOK",          (CmdHandler)_assuan_cmd_setok },
      { "SETCANCEL",      (CmdHandler)_assuan_cmd_setcancel },
      { "GETPIN",         (CmdHandler)_assuan_cmd_getpassphrase },
      { "CONFIRM",        (CmdHandler)_assuan_cmd_confirm },
      { "GETINFO",        (CmdHandler)_assuan_cmd_getinfo },
      { "STOP",           (CmdHandler)_assuan_cmd_stop },
      { NULL, NULL }
    };
  int i, j;
  gpg_error_t rc;

  for (i = j = 0; table[i].name; i++) {
      rc = assuan_register_command(ctx, table[i].name, table[i].handler, nullptr);
      if (rc)
          return rc;
  }
  return 0;
}

QAssuanServer::QAssuanServer(QObject *parent)
    : QThread(parent)
    , secretManager()
    , m_connected(false)
    , m_ctx(nullptr)
    , m_request_stop(false)
{
    gpg_error_t rc;
    int filedesc[2];

    filedesc[0] = 0;
    filedesc[1] = 1;
    rc = assuan_new(&m_ctx);
    if (!rc) rc = assuan_init_pipe_server(m_ctx, filedesc);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to initialize the server: " << gpg_strerror(rc);
        if (m_ctx) assuan_release(m_ctx);
        m_ctx = nullptr;
        return;
    }
    rc = register_commands(m_ctx);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register commands with Assuan: " << gpg_strerror(rc);
        assuan_release(m_ctx);
        m_ctx = nullptr;
        return;
    }

    assuan_set_pointer(m_ctx, this);
    rc = assuan_register_option_handler(m_ctx, (OptionHandler)_option_handler);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register option handler with Assuan: " << gpg_strerror(rc);
        assuan_release(m_ctx);
        m_ctx = nullptr;
        return;
    }
    rc = assuan_register_reset_notify(m_ctx, _reset_handler);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register reset handler with Assuan: " << gpg_strerror(rc);
        assuan_release(m_ctx);
        m_ctx = nullptr;
        return;
    }

    m_connected = true;
}

QAssuanServer::~QAssuanServer()
{
    if (isRunning()) {
        terminate();
        wait(500);
    }
    if (m_connected) {
        assuan_release(m_ctx);
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
    gpg_error_t rc;

    for (;;) {
        rc = assuan_accept(m_ctx);
        if (rc == static_cast<gpg_error_t>(-1))
            break;
        else if (rc) {
            qCWarning(lcSailfishPinentry) << "Assuan accept failed: " << gpg_strerror(rc);
            break;
        }

        rc = assuan_process(m_ctx);
        if (rc) {
            qCWarning(lcSailfishPinentry) << "Assuan processing failed: " << gpg_strerror(rc);
            continue;
        }

        if (m_request_stop) {
            break;
        }
    }
    qCDebug(lcSailfishPinentry) << "Assuan loop finished.";
}

Sailfish::Secrets::Result QAssuanServer::requestPassphrase(QByteArray *passphrase)
{
    passphrase->clear();

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
