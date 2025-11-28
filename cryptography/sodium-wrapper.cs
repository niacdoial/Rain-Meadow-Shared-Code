using System;
using System.Runtime.InteropServices;
// using System.Net;
// using System.Linq;
// using System.IO;
// using System.Collections.Generic;
// using System.Diagnostics;

namespace Sodium {
    public class LibSodium {
        // three gripes about this godawful C library interface definintion
        // - "unsized long long" my fucking tail, because the C integer hierarchy is fucked (but what else is new)
        //   apparently (wikipedia) this is to ensure "at least 64bit" on all platforms but I have no clue if this is supposed to be 64 or 128bit
        // - size_t doesn't exist in csharp (WHY) so we make due with UIntPtr, which is the same where we compile.
        //   If you're curious as to when it can differ, you might want to look as Gankra's blogposts
        //   (in short, "a pointer" and "an offset in memory" are not the same concept and can in fact be different sizes on some hardware)
        // - no const/readonly pointers because declaring what unsafe functions can modify is for chumps apparently
        // - hey also why is a random function using size_t while everything else uses unsized long long??

        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_init();

        // ////////
        // secure randomness
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern void randombytes_buf(byte* buf, UIntPtr size);
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern void sodium_memzero(byte* pnt, UIntPtr len);
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int sodium_memcmp(/*readonly*/ byte* b1_, /*readonly*/ byte* b2_, UIntPtr len);
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern char *sodium_bin2hex(char* hex, UIntPtr hex_maxlen,
                            /*readonly*/ byte* bin, UIntPtr bin_len);

        // ////////
        // secure transmission "box"
        // first the functions that return consts
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_noncebytes();
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_macbytes();
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_publickeybytes();
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_secretkeybytes();
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_messagebytes_max();
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_beforenmbytes();
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern char* crypto_box_primitive();

        // then the functions that actually do stuff
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int crypto_box_keypair(byte* pk, byte* sk);

        /// regenerate pk from sk
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int crypto_scalarmult_base(byte *pk, /*readonly*/ byte *sk);

        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int crypto_box_easy(byte *c, /*readonly*/ byte *m,
                            UInt64 mlen, /*readonly*/ byte *n,
                            /*readonly*/ byte *pk, /*readonly*/ byte *sk);

        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int crypto_box_open_easy(byte *m, /*readonly*/ byte *c,
                                UInt64 clen, /*readonly*/ byte *n,
                                /*readonly*/ byte *pk, /*readonly*/ byte *sk);

        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int crypto_box_beforenm(byte *k, /*readonly*/ byte *pk,
                                /*readonly*/ byte *sk);
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int crypto_box_easy_afternm(byte *c, /*readonly*/ byte *m,
                                    UInt64 mlen, /*readonly*/ byte *n,
                                    /*readonly*/ byte *k);

        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int crypto_box_open_easy_afternm(byte *m, /*readonly*/ byte *c,
                                        UInt64 clen, /*readonly*/ byte *n,
                                        /*readonly*/ byte *k);


        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern UIntPtr crypto_sign_secretkeybytes();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern UIntPtr  crypto_sign_publickeybytes();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern UIntPtr  crypto_sign_messagebytes_max();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern UIntPtr  crypto_sign_bytes();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern const char *crypto_sign_primitive();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public unsafe static extern int crypto_sign_keypair(byte *pk, byte *sk);
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public unsafestatic extern int crypto_sign_detached(byte *sig, UInt64 *siglen_p,
        //                          /*readonly*/ byte *m, UInt64 mlen,
        //                          /*readonly*/ byte *sk);
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public unsafe static extern int crypto_sign_verify_detached(/*readonly*/ byte *sig,
        //                                 /*readonly*/ byte *m,
        //                                 UInt64 mlen,
        //                                 /*readonly*/ byte *pk);


        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public unsafe static extern int crypto_sign_ed25519_sk_to_pk(byte *pk, /*readonly*/ byte *sk);


        // ///////////////////////////////////////////
        // Wrapped part:

        static bool _initialised = false;

        public readonly static int BOX_MAC_SIZE;
        public readonly static int BOX_NONCE_SIZE;
        public readonly static int BOX_PK_SIZE;
        public readonly static int BOX_SK_SIZE;
        public readonly static int BOX_DERVK_SIZE;

        // public readonly static int SIG_HMAC_SIZE;
        // public readonly static int SIG_PK_SIZE;
        // public readonly static int SIG_SK_SIZE;

        static LibSodium() {
            // if (_initialised) return;

            sodium_init();

            BOX_MAC_SIZE = (int)LibSodium.crypto_box_macbytes();
            BOX_NONCE_SIZE = (int)LibSodium.crypto_box_noncebytes();
            BOX_PK_SIZE = (int)LibSodium.crypto_box_publickeybytes();
            BOX_SK_SIZE = (int)LibSodium.crypto_box_secretkeybytes();
            BOX_DERVK_SIZE = (int)LibSodium.crypto_box_beforenmbytes();

            // SIG_HMAC_SIZE = (int)LibSodium.crypto_sign_bytes();
            // SIG_PK_SIZE = (int)LibSodium.crypto_sign_publickeybytes();
            // SIG_SK_SIZE = (int)LibSodium.crypto_sign_secretkeybytes();

            // _initialised = true;
        }

        public static char[] BoxPubKeyToHex(byte[] boxPk) {
            char[] buff = new char[2*BOX_PK_SIZE+1];
            unsafe{
                fixed (char* p_buff = buff)
                fixed (byte* p_pk = boxPk){
                    sodium_bin2hex(
                        p_buff, (UIntPtr)(2*BOX_PK_SIZE+1),
                        p_pk, (UIntPtr)(BOX_PK_SIZE)
                    );
                }
            }
            return buff;
        }

    }
}
