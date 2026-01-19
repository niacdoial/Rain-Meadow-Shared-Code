using System;
using System.Text;
using System.Runtime.InteropServices;
using RainMeadow.Shared;
using RainMeadow;
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

        // Encoding
        public unsafe static extern byte* sodium_bin2hex(/*utf8*/ byte* hex, UIntPtr hex_maxlen,
                            /*readonly*/ byte* bin, UIntPtr bin_len);
        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int sodium_hex2bin(byte* bin, UIntPtr bin_maxlen,
                           /*readonly utf8*/ byte* hex, UIntPtr hex_len,
                           /*readonly*/ byte* ignore, UIntPtr* bin_len,
                           byte** hex_end);

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
        public unsafe static extern /*utf8*/ byte* crypto_box_primitive();

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

        enum Base64Varient
        {
            ORIGINAL = 1, // 01
            ORIGINAL_NO_PADDING = 3, // 11
            URLSAFE =  5, // 101
            URLSAFE_NO_PADDING = 7 // 111
        };

        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr sodium_base64_encoded_len(UIntPtr size, int variant);

        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern int sodium_bin2base64(byte *b64, UIntPtr b64_maxlen, byte *bin, UIntPtr bin_len, int varient);


        [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        public unsafe static extern UIntPtr sodium_base642bin(byte *bin, UIntPtr bin_maxlen, byte *b64,
                      UIntPtr b64_len, byte *ignore, UIntPtr *bin_len,
                      byte **b64_end, int variant);
                                              
        
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern UIntPtr crypto_sign_secretkeybytes();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern UIntPtr  crypto_sign_publickeybytes();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern UIntPtr  crypto_sign_messagebytes_max();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern UIntPtr  crypto_sign_bytes();
        // [DllImport("libsodium.dll", CallingConvention = CallingConvention.Cdecl)]
        // public static extern const /*utf8*/ byte *crypto_sign_primitive();
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

        // static bool _initialised = false;

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

        public static string BinToHex(byte[] binary) {
            byte[] buff = new byte[2*binary.Length+1];

            unsafe{
                fixed (byte* p_buff = buff)
                fixed (byte* p_pk = binary){
                    sodium_bin2hex(
                        p_buff, (UIntPtr)buff.Length,
                        p_pk, (UIntPtr)binary.Length
                    );
                }
            }
            return Encoding.UTF8.GetString(buff);
        }

        public static byte[] HexToBin(string hex) {
            byte[] binary = new byte[(hex.Length-1)/2];
            byte[] buff = Encoding.UTF8.GetBytes(hex.ToCharArray());

            unsafe{
                fixed (byte* p_buff = &buff[0])
                fixed (byte* p_pk = &binary[0]){
                    int errCode = sodium_hex2bin(
                        p_pk, (UIntPtr)binary.Length,
                        p_buff, (UIntPtr)buff.Length,
                        null, null, null
                    );
                }
            }
            return binary;
        }

        public static byte[] ComputeSharedKey(byte[] private_key, byte[] public_key) {
            byte[] shared_key = new byte[LibSodium.BOX_DERVK_SIZE];
            unsafe 
            {
                fixed(byte *p_conn_sk = private_key, p_peer_pk = public_key, p_shk = shared_key) 
                {
                    if (LibSodium.crypto_box_beforenm(p_shk, p_peer_pk, p_conn_sk) != 0) 
                        throw new Exception("failed to precompute shared communication key");
                }
            }
            return shared_key;
        }

        public static byte[]? SodiumDecodePacket(byte[] cyphertext, byte[] nonce, byte[] shared_key) {
            byte[] cleartext = new byte[cyphertext.Length - LibSodium.BOX_MAC_SIZE];
            unsafe {
                fixed (byte *p_shk = shared_key, p_nonce = nonce, p_clear = cleartext, p_cypher = cyphertext)
                {
                    SodiumDecodePacket(p_cypher, cyphertext.Length, p_nonce, nonce.Length, p_shk, shared_key.Length, p_clear);
                }
            }
            return cleartext;
        }

        public unsafe static void SodiumDecodePacket(byte *p_cypher, int cypher_len, 
                byte *p_nonce, int nonce_len, byte *p_shk, int shared_key_len, byte *p_clear) 
        {
            if (cypher_len <= LibSodium.BOX_MAC_SIZE) throw new InvalidProgrammerException("cypher text size less then MAC size");
            if (nonce_len != BOX_NONCE_SIZE) throw new InvalidProgrammerException("nonce length mismatch");
            if (shared_key_len != BOX_DERVK_SIZE) throw new InvalidProgrammerException("shared key length mismatch");
            
            if (LibSodium.crypto_box_open_easy_afternm(p_clear, p_cypher, (ulong)cypher_len, p_nonce, p_shk) != 0) 
                throw new Exception("crypto_box_easy_afternm failed");
            return;
        }



        public static int SodiumEncodePacketSize(int clearTextLen) => clearTextLen + LibSodium.BOX_MAC_SIZE;
        public static void SodiumEncodePacket(byte[] cleartext, byte[] nonce, byte[] shared_key, ref byte[]? cyphertext) 
        {
            if (cyphertext is null) cyphertext = new byte[cleartext.Length + LibSodium.BOX_MAC_SIZE];
            unsafe
            {
                fixed (byte *p_clear = cleartext, p_cypher = cyphertext, p_shk = shared_key, p_nonce = nonce)
                {
                    SodiumEncodePacket(p_clear, cleartext.Length, p_nonce, nonce.Length, p_shk, shared_key.Length, p_cypher);
                }
            }
        }

        public unsafe static void SodiumEncodePacket(byte *p_clear, int clear_len, 
                byte *p_nonce, int nonce_len, byte *p_shk, int shared_key_len, byte *p_cypher) 
        {
            if (clear_len == 0) throw new InvalidProgrammerException("Attempted to encode empty packet");
            if (nonce_len != BOX_NONCE_SIZE) throw new InvalidProgrammerException("nonce length mismatch");
            if (shared_key_len != BOX_DERVK_SIZE) throw new InvalidProgrammerException("shared key length mismatch");
            
            if (LibSodium.crypto_box_easy_afternm(p_cypher, p_clear, (ulong)clear_len, p_nonce, p_shk) != 0) 
                throw new Exception("crypto_box_easy_afternm failed");
            return;
        }
    }
}
