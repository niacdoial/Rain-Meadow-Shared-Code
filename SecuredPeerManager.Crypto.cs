using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
//using UnityEngine;
using Sodium;

namespace RainMeadow.Shared
{

    // /////// Summary of the cryptography involved:
    // - most of the Good Shtuff comes from plain LibSodium boxes,
    //   used to encrypt player-server and player-player communications
    // - The server's pubkey is communicated ahead of time,
    //   so the clients can detect a MITM and GTFO.
    //   (the server doesn't notice it, but once the actual player bails,
    //   the middlebox has the same power as another prospective player, which anyone can be)
    //   - the server's pubkey is usually given by the HTTPS-based matchmaker
    //     (so we have a full chain of trust from the TLS certificate root to the lobby server's pubkey)
    //   - or it is manually input when direct-connecting (long connection codes but this doesn't matter)

    // - the server serves the clients' pubkeys to each other, so no MITM in player-player communications.
    // - initial player->server needs to give the pubkey in cleartext (or through an anonimised box if needed),
    //   so the keypair will be regen'd between matches for anonymity's sake
    //   (stopping people from tracking users across IP addresses. Though we'll need the anonimised boxed
    //    if we start handling players that change IP addresses mid-game)
    //   This rotation between games also provides forward secrecy
    //   (key compromises don't let a third party decript everything a player ever did, only a sigle session)
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
    // LPKT (v1):  0 -> v1, reliable
    //             1 -> v1, unreliable
    //             3 -> v1, heartbeat
    //
    //
    // ----
    // player_sig: player_spk, hmac(version_u16,player_pk,server_pk)
    // p2p_sig: player_spk, hmac(version_u16, player_spk, peer_spk)
    //
    //
    //
    // //////////// future plans
    // - there's a persistant player ID though, which comes in the form of a signing-only key
    // - (this second part *definitely* counts as "rolling my own crypto" but the stakes are way lower.
    //    As long as the actual encryption is bug-free, only legitimate players from that lobby may see stuff)
    // - It is used to sign the pubkey pair (from the previous step), plus other things, to prove the identity of the players to each other
    //   - the server doesn't have an identity
    //   - this allows friends-only lobbies, banlists (up until somebody scrambles their ID to escape it)
    //   - and dev recognition!
    // - open questions:
    //   - if you use this, you need a way to have the signature work even when proxying a message through the server
    //     (and when switching from direct to proxied communications)
    //     how do you do it?
    //     - I can think of be two-layer encryption (bleh)
    //     - Encryption plus signing inside (probably slower!)
    //     - having some destination ID in plaintext
    //       (boo! but at the same time can't a network observer compute that from otherwise-available data anyway?)
    //     - another idea: generate a "proxying key"


    public partial class SecuredPeerManager : IDisposable
    {
        byte[] private_key;
        byte[] public_key;
        void ResetKeys() 
        {
            if (public_key is null) public_key = new byte[LibSodium.BOX_PK_SIZE];
            if (private_key is null) private_key = new byte[LibSodium.BOX_SK_SIZE];
            
            unsafe
            {
                fixed (byte *p_conn_sk = this.private_key, p_conn_pk = this.public_key)
                {
                    int errCode = LibSodium.crypto_box_keypair(p_conn_pk, p_conn_sk);
                    if (errCode != 0) throw new Exception("failed to generate connection keypair: errno "+errCode.ToString());
                }
                
                // fixed (byte* p_id_sk = &this.identity_sk[0], p_id_pk = &this.identity_pk[0])
                // {
                //     int errCode = LibSodium.crypto_sign_keypair(p_id_pk, p_id_sk);
                //     if (errCode !=0) {
                //         throw new Exception("failed to generate identity keypair: errno "+errCode.ToString());
                //     }
                // }
            }

            foreach (RemotePeer peer in peers)
            {
                peer.shared_key = null;
                peer.acked_pubkey = false;
            }

            Me.publicKey = public_key;
        }

        void ComputeSharedKey(RemotePeer peer) {
            if (peer.shared_key == null) 
            {
                peer.shared_key = new byte[LibSodium.BOX_DERVK_SIZE];
                unsafe 
                {
                    fixed(byte *p_conn_sk = this.private_key, p_peer_pk = peer.id.publicKey, p_shk = peer.shared_key) 
                    {
                        if (LibSodium.crypto_box_beforenm(p_shk, p_peer_pk, p_conn_sk) != 0) 
                            throw new Exception("failed to precompute shared communication key");
                    }
                }
            }
        }

        byte[]? SodiumDecodePacket(byte[] cyphertext, byte[] nonce, RemotePeer peer) {
            if (cyphertext.Length <= LibSodium.BOX_MAC_SIZE) throw new InvalidProgrammerException("cypher text size less then MAC size");
            byte[] cleartext = new byte[cyphertext.Length - LibSodium.BOX_MAC_SIZE];
            ComputeSharedKey(peer);
            unsafe {
                fixed (byte *p_shk = peer.shared_key, p_once = nonce, p_clear = cleartext, p_cypher = cyphertext)
                {
                    if (LibSodium.crypto_box_open_easy_afternm(p_clear, p_cypher, (ulong)cyphertext.Length, p_once, p_shk) != 0) 
                        return null;
                }
            }
            return cleartext;
        }

        byte[]? SodiumEncodePacket(byte[] cleartext, byte[] nonce, RemotePeer peer) 
        {
            if (cleartext.Length == 0) throw new InvalidProgrammerException("Attempted to encode empty packet");
            if (LibSodium.BOX_NONCE_SIZE != nonce.Length) throw new InvalidProgrammerException("nonce length mismatch");
            byte[] cyphertext = new byte[cleartext.Length + LibSodium.BOX_MAC_SIZE];
            ComputeSharedKey(peer);
            unsafe {
                fixed (byte* p_shk = &peer.shared_key[0], p_once = &nonce[0], p_clear = &cleartext[0], p_cypher = &cyphertext[0]) {
                    if (LibSodium.crypto_box_easy_afternm(p_cypher, p_clear, (ulong)cleartext.Length, p_once, p_shk) != 0) 
                        throw new Exception("crypto_box_easy_afternm failed");
                }
            }
            return cyphertext;
        }
        byte[] MakeUnreliableNonce() {
            byte[] nonce = new byte[LibSodium.BOX_NONCE_SIZE];
            unsafe {
                fixed (byte* p_once = &nonce[0]) {
                    LibSodium.randombytes_buf(p_once, (UIntPtr)LibSodium.BOX_NONCE_SIZE);
                }
            }
            return nonce;
        }

        byte[] MakeReliableNonce(ulong order) {
            byte[] nonce = BitConverter.GetBytes(order);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(nonce);
            }

            int initialSize = LibSodium.BOX_NONCE_SIZE - nonce.Length;
            Array.Resize(ref nonce, LibSodium.BOX_NONCE_SIZE);
            if (initialSize < 0) return nonce;
            unsafe 
            {
                fixed (byte* p_once = nonce)
                {
                    LibSodium.sodium_memzero(p_once + initialSize, (UIntPtr)(LibSodium.BOX_NONCE_SIZE - initialSize));
                }
            }
            return nonce;
        }
    }
}
