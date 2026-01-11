using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Sodium;

namespace RainMeadow.Shared
{

    public class PeerId {

        // TODO: ClearTextOnly reception is jank: lobby enumeration needs to feed the pubkeys
        public enum PeerStatus: byte {
            ClearTextOnly = 0,  // network-local broadcast purposes, also allowed for the BlackHole placeholder
            Unknown,  // one current use case: connect to a server then asking the user to double-check the pubkey
            Connected,  // Has a known connection pubkey
        }

        public PeerStatus status;
        public IPEndPoint endPoint;
        public byte[] boxPubkey;

        public PeerId(IPEndPoint endPoint, byte[] boxPubkey) {
            this.status = PeerStatus.Connected;
            this.endPoint = endPoint;
            this.boxPubkey = boxPubkey;
            if (boxPubkey != null && boxPubkey.Length != LibSodium.BOX_PK_SIZE) {
                throw new Exception("malformed pubkey: wrong size");
            }
        }
        public static PeerId MakeClearText(IPEndPoint endPoint) {
            PeerId newSelf = new PeerId(endPoint, null);
            newSelf.status = PeerStatus.ClearTextOnly;
            return newSelf;
        }
        public static PeerId MakeUnknown(IPEndPoint endPoint) {
            if (!SharedPlatform.PlatformPeerManager.allowPeerCreationWithoutKey) {
                throw new Exception("Cannot create unknown-status PeerIDs currently");
            }
            PeerId newSelf = new PeerId(endPoint, null);
            newSelf.status = PeerStatus.Unknown;
            return newSelf;
        }

        public bool Equals(object obj)
        {
            return Equals(obj as PeerId);
        }
        public bool Equals(PeerId id)
        {
            if (this.status == PeerStatus.Connected && id.status == PeerStatus.Connected) {
                return ComparePubKeys(this.boxPubkey, id.boxPubkey);
            } else if (this.status == PeerStatus.Unknown && id.status == PeerStatus.Unknown) {
                return  PeerManager.CompareIPEndpoints(this.endPoint, id.endPoint);
            } else if (this.status == PeerStatus.ClearTextOnly && id.status == PeerStatus.ClearTextOnly) {
                return  PeerManager.CompareIPEndpoints(this.endPoint, id.endPoint);
            } else {
                return false;
            }
        }

        public static bool operator ==(PeerId lhs, PeerId rhs)
        {
            return lhs is null ? rhs is null : lhs.Equals(rhs);
        }
        public static bool operator !=(PeerId lhs, PeerId rhs) => !(lhs == rhs);

        public static bool ComparePubKeys(byte[] first, byte[] second) {
            unsafe {
                fixed (byte* p_thPk = first, p_otPk = second) {
                    return LibSodium.sodium_memcmp(p_thPk, p_otPk, (UIntPtr)LibSodium.BOX_PK_SIZE)==0;
                }
            }
        }

        /// like Equals, but assumes "other" *might* be an updated version of this, and if it is, update this to match
        public bool CompareAndUpdate(PeerId other) {
            // note that this equality function just means "are we sure this is the same peer?"
            if (this.status == PeerStatus.Unknown && other.status == PeerStatus.Connected) {
                if (PeerManager.CompareIPEndpoints(this.endPoint, other.endPoint)) {
                    this.boxPubkey = other.boxPubkey;
                    this.status = PeerStatus.Connected;
                    return true;
                } else {
                    return false;
                }
            } else {
                return Equals(other);
            }
        }

        public bool isLoopback()
        {
            // TODO: determine how a self PeerId is emitted
            if (endPoint is null) return false;
            if (SharedPlatform.PlatformPeerManager?.port != endPoint.Port) return false;
            return PeerManager.isLoopback(endPoint.Address);
        }
        public bool isNetworkLocal()
        {
            if (endPoint is null) return false;
            return PeerManager.isEndpointLocal(endPoint);
        }

        // Blackhole Endpoint
        // https://superuser.com/questions/698244/ip-address-that-is-the-equivalent-of-dev-null
        public static IPEndPoint BlackHoleEndPoint = new IPEndPoint(IPAddress.Parse("253.253.253.253"), 999);
        public bool isBlackHole()
        {
            // note that BlackHole PeerIDs are allowed to have pubkeys, because they are a signal that packets to them must be proxied
            return PeerManager.CompareIPEndpoints(endPoint, BlackHoleEndPoint);
        }
        public void ValidateCryptStatus(bool peerIsSender = false, bool forClearText = false, bool internalChecksOnly = false) {
            switch (this.status) {
                case PeerStatus.Unknown:
                    if (peerIsSender && !internalChecksOnly) {
                        throw new Exception("assertion failed: unknown-encryption peers can only be message recipients, not senders");
                    }
                    if (forClearText && !internalChecksOnly) {
                        throw new Exception("assertion failed: peer must be suited for encrypted");
                    }
                    if (isBlackHole()) {
                        throw new Exception("assertion failed: BlackHole peers must be cleartext");
                    } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                        throw new Exception("assertion failed: Broadcast peers must be cleartext");
                    }
                    break;
                case PeerStatus.Connected:
                    if (forClearText && !internalChecksOnly) {
                        throw new Exception("assertion failed: peer must be suited for encrypted");
                    }
                    if (isBlackHole()) {
                        throw new Exception("assertion failed: BlackHole peers must be cleartext");
                    } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                        throw new Exception("assertion failed: Broadcast peers must be cleartext");
                    }
                    if ((this.boxPubkey?.Length ?? 0) != LibSodium.BOX_PK_SIZE) {
                        throw new Exception("assertion failed: Correctly initialised pubkey");
                    }
                    break;
                case PeerStatus.ClearTextOnly:
                    if (! (forClearText || internalChecksOnly)) {
                        throw new Exception("assertion failed: peer must be suited for cleartext communications");
                    }
                    if ((peerIsSender || internalChecksOnly) && isNetworkLocal()) {
                        // only network-local packet entry
                        return;
                    } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                        return;
                    }
                    throw new Exception("assertion failed: Cleartext peers can only exist for local-network broacasts");
                    break;
                default:
                    throw new Exception("bad code update: failed to handle new PeerId status");
                    break;
            }
        }
    }


    public partial class PeerManager : IDisposable
    {
        class RemotePeer : IDisposable {
            // data for connection itself
            public PeerId id;
            public byte[] connection_computed_k;


            public ulong TicksSinceLastIncomingPacket = 0;
            public ulong OutgoingPacketAcummulator = 0;

            public Queue<byte[]> outgoingpacket = new Queue<byte[]>();
            public ulong wanted_acknowledgement = 0;  // the 'packet ID' of the last reliable packet ack'd by peer (1-indexed)
            public ulong remote_acknowledgement = 0;  // the 'packet ID' of the last reliable packet recv'd by us  (1-indexed)
            public bool need_begin_conversation_ack = true;

            void IDisposable.Dispose() {
                unsafe {
                    fixed (byte* p_csk = this.connection_computed_k) {
                        LibSodium.sodium_memzero(p_csk, (UIntPtr)LibSodium.BOX_DERVK_SIZE);
                    }
                }
            }
        }

        public PeerId BlackHole = null;
        List<RemotePeer> peers = new();
        public bool allowPeerCreationWithoutKey = false;

        public delegate void OnPeerForgotten_t(PeerId peerId);
        public event OnPeerForgotten_t OnPeerForgotten = delegate { };
        public void Run_OnPeerForgotten(PeerId peerId) {
            OnPeerForgotten.Invoke(peerId);
        }

        public delegate void ConfirmCallback_t(string template, string data, ref bool canProceed);
        public event ConfirmCallback_t ConfirmCallback = delegate { };
        public bool Run_ConfirmCallback(string template, string data) {
            bool canProceed = true;
            ConfirmCallback.Invoke(template, data, ref canProceed);
            return canProceed;
        }

        RemotePeer? GetRemotePeer(PeerId peerId, bool makeOrUpdate = false) {
            if (makeOrUpdate) {
                RemotePeer? peer = peers.FirstOrDefault(x => x.id.CompareAndUpdate(peerId));
                if (peer == null) {
                    peerId.ValidateCryptStatus(false, false, true);
                    peer = new RemotePeer() {id = peerId};
                    if (peerId.status != PeerId.PeerStatus.ClearTextOnly) {
                        peers.Add(peer);  // Cleartext (=broadcast) peers are not to be remembered
                    }
                }
                return peer;
            } else {
                return peers.FirstOrDefault(x => x.id == peerId);
            }
        }

        public void EnsureRemotePeerCreated(PeerId peerId) {
            GetRemotePeer(peerId, true);
        }

        void ForgetPeer(RemotePeer peer) {
            peers.Remove(peer);  // remove first, in case this peer's removal callback recurses into here
            Run_OnPeerForgotten(peer.id);
        }
        public void ForgetPeer(PeerId peerId) {
            var remove_peers = peers.FindAll(x => peerId == x.id);
            foreach (RemotePeer peer in remove_peers) {
                ForgetPeer(peer);
            }
        }

        public void ForgetAllPeers() {
            var remove_peers = peers.ToList();
            foreach (RemotePeer peer in remove_peers) {
                ForgetPeer(peer);
            }
        }
    }
}
