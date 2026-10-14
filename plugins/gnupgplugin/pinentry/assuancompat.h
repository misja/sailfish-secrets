/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef PINENTRY_ASSUANCOMPAT_H
#define PINENTRY_ASSUANCOMPAT_H

#include <assuan.h>
#include <gpg-error.h>

#if defined(ASSUAN_VERSION_NUMBER) && ASSUAN_VERSION_NUMBER >= 0x020000
#define PINENTRY_MODERN_ASSUAN 1
typedef gpg_error_t PinentryAssuanError;
#else
#define PINENTRY_MODERN_ASSUAN 0
typedef int PinentryAssuanError;
#endif

typedef PinentryAssuanError (*PinentryCommandHandler)(assuan_context_t, char *);

inline gpg_error_t pinentryAssuanInit(assuan_context_t *ctx, int fds[2])
{
#if PINENTRY_MODERN_ASSUAN
    gpg_error_t rc = assuan_new(ctx);
    if (rc) return rc;
    assuan_fd_t pipeFds[2] = { fds[0], fds[1] };
    return assuan_init_pipe_server(*ctx, pipeFds);
#else
    return assuan_init_pipe_server(ctx, fds);
#endif
}

inline void pinentryAssuanRelease(assuan_context_t ctx)
{
    if (!ctx) return;
#if PINENTRY_MODERN_ASSUAN
    assuan_release(ctx);
#else
    assuan_deinit_server(ctx);
#endif
}

inline gpg_error_t pinentryAssuanRegister(assuan_context_t ctx,
                                        const char *name, PinentryCommandHandler handler)
{
#if PINENTRY_MODERN_ASSUAN
    return assuan_register_command(ctx, name, handler, 0);
#else
    return assuan_register_command(ctx, name, handler);
#endif
}

inline const char *pinentryAssuanStrerror(PinentryAssuanError rc)
{
#if PINENTRY_MODERN_ASSUAN
    return gpg_strerror(rc);
#else
    return assuan_strerror(rc);
#endif
}
#endif
