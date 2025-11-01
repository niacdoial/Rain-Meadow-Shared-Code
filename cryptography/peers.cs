using System;
using System.Net;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using LibSodium;


namespace RainMeadow.Shared;
{

    // /////// Summary of the cryptography involved:
    // - most of the Good Shtuff comes from plain LibSodium boxes,
    //   used to encrypt player-server and player-player communications
    // - The server's pubkey is communicated ahead of time,
    //   so the clients can detect a MITM and GTFO.
    //   - given by the HTTPS-based matchmaker (so we have a full chain of trust from the TLS certificate root to the lobby server's pubkey)
    //   - or manually input when direct-connecting (MEH-tier UX. We could allow to bypass that but... yeag.)
    //   (the server doesn't notice it, but at this point the middleman is just another prospective player)
    // - the server serves the clients' pubkeys to each other, so no MITM in player-player communications.
    // - initial player->server needs to give the pubkey in cleartext, so the keypair will be regen'd
    //   between matches for anonymity's sake (this pubkey stops people from tracking users across IP addresses)
    //
    // - there's a persistant player ID though, which comes in the form of a signing-only key
    // - (this second part *definitely* counts as "rolling my own crypto" but the stakes are way lower.
    //    As long as the actual encryption is bug-free, only legitimate players from that lobby may see stuff)
    // - It is used to sign the pubkey pair (from the previous step), plus other things, to prove the identity of the players to each other
    //   - the server doesn't have an identity
    //   - this allows friends-only lobbies, banlists (up until somebody scrambles their ID to escape it)
    //   - and dev recognition!
    //
    // /////// Things mitigated
    //
    //
    // /////// packet format
    //
    // // THREE version numbers:
    // // - plaintext packet format (dictates how to read the plaintext and the start of the ciphertext, including the next number)
    // // - ciphertext packet format (dictates how the ciphertext is organised in general, what the packet type enum actually maps to)
    // // - full-meadow format, dictates the RPC-level communication format
    //
    // initial_p2s_packet: GLPKT, player_pk, nonce, boxsz_u16, box(LPKT, player_sig, contents)
    // server_response: GLPKT, nonce, boxsz_u16, box(LPKT, contents)
    // initial_p2p_packet: GLPKT, nonce, boxsz_u16, box(LPKT, p2p_sig, contents)
    //
    // any_following_packet: GLPKT, nonce, boxsz_u16, box(LPKT, contents)
    //
    // GLPKT: 0 -> v1, cleartext network-local broadcast
    //        1 -> v1, only box
    //        2 -> v1, comm pubkey prefaces box
    // LPKT (v1):  0 -> v1, contains psig, reliable
    //             1 -> v1, contains psig, unreliable
    //             2 -> v1, reliable
    //             3 -> v1, unreliable
    //             4 -> v1, heartbeat
    //
    //
    // ----
    // player_sig: player_spk, hmac(version_u16,player_pk,server_pk)
    // p2p_sig: player_spk, hmac(version_u16, player_spk, peer_spk)
    //

    public class CryptoPlatform {
        public const size_t BOX_MAC_SIZE = LibSodium.crypto_box_macbytes();
        public const size_t BOX_NONCE_SIZE = LibSodium.crypto_box_noncebytes();
        public const size_t BOX_PK_SIZE = LibSodium.crypto_box_publickeybytes();
        public const size_t BOX_SK_SIZE = LibSodium.crypto_box_secretkeybytes();
        public const size_t BOX_DERVK_SIZE = LibSodium.crypto_box_beforenmbytes();

        public const size_t SIG_HMAC_SIZE = LibSodium.crypto_sign_bytes();
        public const size_t SIG_PK_SIZE = LibSodium.crypto_sign_publickeybytes();
        public const size_t SIG_SK_SIZE = LibSodium.crypto_sign_secretkeybytes();

        SelfCrypto ownCredentials = null;


        CryptoPlatform() {

        }



    }

    public class SelfCrypto {
    }


    public class CryptoPeer {
        PeerState state;



    }
