using System;
// using System.Net;
// using System.Linq;
// using System.IO;
// using System.Collections.Generic;
// using System.Diagnostics;



namespace LibSodium {

class LibSodium {

    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    int sodium_init(void);

    // ////////
    // secure randomness
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void randombytes_buf(void * const buf, const size_t size);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void sodium_memzero(void * const pnt, const size_t len);

    // ////////
    // secure transmission "box"
    // first the functions that return consts
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_box_noncebytes(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_box_macbytes(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_box_publickeybytes(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_box_secretkeybytes(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_box_messagebytes_max(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_box_beforenmbytes(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    const char *crypto_box_primitive(void);

    // then the functions that actually do stuff
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_box_keypair(unsigned char* pk, unsigned char* sk);

    /// regenerate pk from sk
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_scalarmult_base(unsigned char *pk, const unsigned char *sk);

    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_box_easy(unsigned char *c, const unsigned char *m,
                        unsigned long long mlen, const unsigned char *n,
                        const unsigned char *pk, const unsigned char *sk);

    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_box_open_easy(unsigned char *m, const unsigned char *c,
                             unsigned long long clen, const unsigned char *n,
                             const unsigned char *pk, const unsigned char *sk);

    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    int crypto_box_beforenm(unsigned char *k, const unsigned char *pk,
                            const unsigned char *sk);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    int crypto_box_easy_afternm(unsigned char *c, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *n,
                                const unsigned char *k);

    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    int crypto_box_open_easy_afternm(unsigned char *m, const unsigned char *c,
                                     unsigned long long clen, const unsigned char *n,
                                     const unsigned char *k);


    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t crypto_sign_secretkeybytes(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_sign_publickeybytes(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_sign_messagebytes_max(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    size_t  crypto_sign_bytes(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    const char *crypto_sign_primitive(void);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                             const unsigned char *m, unsigned long long mlen,
                             const unsigned char *sk);
    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    int crypto_sign_verify_detached(const unsigned char *sig,
                                    const unsigned char *m,
                                    unsigned long long mlen,
                                    const unsigned char *pk);


    [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
    int crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);

}
}
