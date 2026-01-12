using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Sodium;

namespace RainMeadow.Shared
{    
    public class SecuredPeerId : IEquatable<SecuredPeerId> {
        public enum PeerStatus: byte {
            // ClearTextOnly = 0,  // network-local broadcast purposes, also allowed for the BlackHole placeholder
            PendingPublicKey,  // one current use case: connect to a server then asking the user to double-check the pubkey
            Connected,  // Has a known connection pubkey
        }

        public PeerStatus Status 
        { 
            get
            {
                if (publicKey != null) return PeerStatus.Connected;   
                return PeerStatus.PendingPublicKey;
            }
        }

        public IPEndPoint endPoint;
        public byte[]? publicKey;
        public SecuredPeerId(IPEndPoint endPoint, byte[]? boxPubkey) 
        {
            this.endPoint = endPoint;
            this.publicKey = boxPubkey;
            if (boxPubkey != null && boxPubkey.Length != LibSodium.BOX_PK_SIZE) 
                throw new Exception("malformed pubkey: wrong size");
        }

        public override bool Equals(object obj) => obj is SecuredPeerId id? Equals(id) : false;
        public bool Equals(SecuredPeerId? id) => id == null? false : SharedPlatform.CompareIPEndpoints(this.endPoint, id.endPoint);
        public static bool operator ==(SecuredPeerId? a,SecuredPeerId? b) => a is null? b is null : a.Equals(b);
        public static bool operator !=(SecuredPeerId? a,SecuredPeerId? b) => !(a == b);
        public override int GetHashCode() => endPoint.GetHashCode();


        public bool CompareAndUpdate(SecuredPeerId? other) {
            // note that this equality function just means "are we sure this is the same peer?"
            if (other is SecuredPeerId id && Equals(id))
            {
                if (this.Status == PeerStatus.PendingPublicKey)
                {
                    this.publicKey = other.publicKey;
                }
                
                return true;
            }
            return false;
        }

        public bool IsLoopback() => SharedPlatform.IsLoopback(endPoint.Address);
        public bool IsNetworkLocal() => SharedPlatform.IsEndpointLocal(endPoint.Address);
        public void ValidateCryptStatus(bool peerIsSender = false, bool forClearText = false, bool internalChecksOnly = false) 
        {
            switch (this.Status) {
                case PeerStatus.PendingPublicKey:
                    if (peerIsSender && !forClearText && !internalChecksOnly) {
                        throw new Exception("assertion failed: unknown-encryption peers can only be message recipients, not senders");
                    }
                    break;
                case PeerStatus.Connected:
                    // if (forClearText && !internalChecksOnly) {
                    //     throw new Exception("assertion failed: peer must be suited for encrypted");
                    // }s
                    if ((this.publicKey?.Length ?? 0) != LibSodium.BOX_PK_SIZE) {
                        throw new Exception("assertion failed: Incorrectly initialised pubkey");
                    }
                    break;
                // case PeerStatus.ClearTextOnly:
                //     if (!(forClearText || internalChecksOnly)) {
                //         throw new Exception("assertion failed: peer must be suited for cleartext communications");
                //     }
                //     if ((peerIsSender || internalChecksOnly) && IsNetworkLocal()) {
                //         // only network-local packet entry
                //         return;
                //     } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                //         return;
                //     }
                //     throw new Exception("assertion failed: Cleartext peers can only exist for local-network broacasts");
                default:
                    throw new Exception("bad code update: failed to handle new PeerId status");
            }
        }

        public override string ToString() => ToString(true);
        public string ToString(bool debug)
        {
            StringBuilder builder = new StringBuilder();
            if (publicKey != null) 
            {
                builder.Append(LibSodium.BinToHex(publicKey));
            }

            builder.Append(endPoint);

            if (debug)
            {
                builder.Append($" [is machine local: {IsLoopback()}, is network local: {IsNetworkLocal()}]");
            }
            return builder.ToString();
        }



        public static SecuredPeerId Deserialize(BinaryReader reader, SecuredPeerId from)
        {
            ushort port = reader.ReadUInt16();
            if (reader.ReadBoolean()) // isMe
            {
                return new SecuredPeerId(new IPEndPoint(IPAddress.Loopback, port), null);
            }
            else if (reader.ReadBoolean()) // isThem
            {
                return new SecuredPeerId(new IPEndPoint(from.endPoint.Address, port), null);
            }
            else
            {
                IPAddress address = new IPAddress(reader.ReadBytes(reader.ReadByte()));
                return new SecuredPeerId(new IPEndPoint(address, port), null);
            }
        }

        public void Serialize(BinaryWriter writer, SecuredPeerId to) 
        {
            // writer.Write(publicKey != null);
            // if (publicKey != null) writer.Write(publicKey);
            writer.Write((ushort)endPoint.Port);
            bool isLoopback = IsLoopback();
            writer.Write(isLoopback);
            if (!isLoopback)
            {
                bool isThem = SharedPlatform.CompareIPEndpoints(to.endPoint, endPoint);
                writer.Write(isThem);

                if (!isThem)
                {
                    writer.Write((byte)endPoint.Address.GetAddressBytes().Length);
                    writer.Write(endPoint.Address.GetAddressBytes());
                }
            }
        }

        /// the functions that (de)serialize multiple endpoints at once can deal with the sender seeing itself differently as everyone else.
        /// The functions that do not need a separate mechanism to deal with this.
        public static void SerializeArray(BinaryWriter writer, SecuredPeerId?[] peers, SecuredPeerId addressedto, bool nullable = false) 
        {
            writer.Write((byte)peers.Length);   
            foreach (SecuredPeerId? peer in peers) 
            {
                if (nullable)
                {
                    writer.Write(peer is null);
                    if (peer is null) continue;
                }
                else if (peer is null) throw new InvalidProgrammerException("Can't serialize null in non nullable array");

                writer.Write((ushort)peer.endPoint.Port);
                bool isLoopback = peer.IsLoopback();
                writer.Write(isLoopback);
                if (!isLoopback)
                {
                    bool isThem = SharedPlatform.CompareIPEndpoints(addressedto.endPoint, peer.endPoint);
                    writer.Write(isThem);

                    if (!isThem)
                    {
                        writer.Write((byte)peer.endPoint.Address.GetAddressBytes().Length);
                        writer.Write(peer.endPoint.Address.GetAddressBytes());
                    }
                }
            }
        }

        public static SecuredPeerId?[] DeserializeArray(BinaryReader reader, SecuredPeerId fromWho, bool nullable = false) 
        {
            SecuredPeerId?[] ret = new SecuredPeerId[reader.ReadByte()];
            for (int i = 0; i < ret.Length; i++) 
            {
                if (nullable)
                {
                    if (reader.ReadBoolean())
                    {
                        ret[i] = null;
                        continue;
                    }
                }

                ushort port = reader.ReadUInt16();
                if (reader.ReadBoolean()) // isMe
                {
                    ret[i] = new SecuredPeerId(new IPEndPoint(IPAddress.Loopback, port), null);
                }
                else if (reader.ReadBoolean()) // isThem
                {
                    ret[i] = new SecuredPeerId(new IPEndPoint(fromWho.endPoint.Address, port), null);
                }
                else
                {
                    IPAddress address = new IPAddress(reader.ReadBytes(reader.ReadByte()));
                    ret[i] = new SecuredPeerId(new IPEndPoint(address, port), null);
                }
            }

            return ret;
        }

        public static SecuredPeerId? GetPeerIdByName(string name) 
        {
            var parts = name.Split('@');
            IPEndPoint? endPoint = null;

            if (parts.Count() == 2) 
            {
                if (parts[0].Length != 2*LibSodium.BOX_PK_SIZE) return null;
                endPoint = SharedPlatform.GetEndPointByName(parts[1]);
                if (endPoint is null) return null;
                byte[] pubKey = LibSodium.HexToBin(parts[0]);
                return new SecuredPeerId(endPoint, pubKey);
            } 
            else if (parts.Count() == 1) 
            {
                endPoint = SharedPlatform.GetEndPointByName(parts[0]);
                if (endPoint is null) return null;
                return new SecuredPeerId(endPoint, null);
            } 
            else 
            {
                return null;
            }
        }
    }

    public partial class SecuredPeerManager : IDisposable
    {
        public struct OutgoingPacket
        {
            public int attempts;
            public byte[] data;
            public bool boxed;
        }

        public class RemotePeer : IDisposable 
        {
            private SecuredPeerManager manager;

            
            // data for connection itself
            public SecuredPeerId id;
            public bool acked_pubkey = false;

            public ulong lastIncomingPacketTick = 0;
            public ulong lastOutgoingTick = 0;

            public Queue<OutgoingPacket> outgoingPackets = new Queue<OutgoingPacket>();
            public ulong wanted_acknowledgement = 0;  // the 'packet ID' of the last reliable packet ack'd by peer (1-indexed)
            public ulong remote_acknowledgement = 0;  // the 'packet ID' of the last reliable packet recv'd by us  (1-indexed)
            

            public RemotePeer(SecuredPeerManager manager, SecuredPeerId id)
            {
                this.manager = manager;
                lastIncomingPacketTick = SharedPlatform.TimeMS;
                lastOutgoingTick = SharedPlatform.TimeMS;
                this.id = id;
            }


            public void Update(ulong tick)
            {
                ulong tickSinceLastPacket = tick - lastIncomingPacketTick;
                if (tickSinceLastPacket >= SharedPlatform.timeoutTime)
                {
                    SharedCodeLogger.Error($"Forgetting {id} due to Timeout, Timeout is {SharedPlatform.timeoutTime}ms");
                    manager.ForgetPeer(this);
                    return;
                }

                ulong tickSinceLastOutgoing = tick - lastOutgoingTick;
                while (tickSinceLastOutgoing > SharedPlatform.heartbeatTime)
                {
                    lastOutgoingTick += SharedPlatform.heartbeatTime;
                    tickSinceLastOutgoing = tick - lastOutgoingTick;
                    if (outgoingPackets.Any())
                    {
                        OutgoingPacket packet = outgoingPackets.Peek();
                        SecurityFlags flags = 0;

                        if (packet.attempts > 0)
                        {
                            packet.attempts--;
                            if (packet.attempts == 0)
                            {

                                // we failed to send it. 
                                wanted_acknowledgement++;
                                outgoingPackets.Dequeue();
                            }
                        }
                        
                        if (!acked_pubkey) flags = flags | SecurityFlags.SendPubKey;
                        if (packet.boxed) flags = flags | SecurityFlags.Boxed;
                        manager.SendRaw(packet.data, this, PacketFlags.Reliable, flags);
                    }
                    else
                    {
                        manager.SendRaw(
                            Array.Empty<byte>(),
                            this,
                            PacketFlags.Unreliable,
                            acked_pubkey? SecurityFlags.ClearText : SecurityFlags.SendPubKey
                        );
                    }
                }
            }            

            bool disposed;
            public byte[]? shared_key;
            public void Dispose() {
                if (shared_key is not null)
                {
                    unsafe 
                    {
                        fixed (byte* p_csk = this.shared_key) {
                            LibSodium.sodium_memzero(p_csk, (UIntPtr)LibSodium.BOX_DERVK_SIZE);
                        }
                    }
                }

                disposed = false;
            }  

            ~RemotePeer()
            {
                Dispose();
            }
        }

            List<RemotePeer> peers = new();
            public RemotePeer? GetRemotePeer(SecuredPeerId peerId, bool make = false) 
            {
                RemotePeer? peer = peers.FirstOrDefault(x => x.id.CompareAndUpdate(peerId));
                if (make && peer == null) 
                {
                    peerId.ValidateCryptStatus(false, false, true);
                    peer = new RemotePeer(this, peerId);
                    peers.Add(peer);
                }

                return peer;
            }

            public delegate void OnPeerForgotten_t(RemotePeer peerId);
            public event OnPeerForgotten_t OnPeerForgotten = delegate { };

            public void ForgetPeer(RemotePeer peer)
            {
                if (peers.Contains(peer))
                {
                    peer.Dispose();
                    peers.Remove(peer);
                    OnPeerForgotten.Invoke(peer);
                }
            }

            public void ForgetPeer(SecuredPeerId peerId) 
            {
                foreach (RemotePeer peer in peers.Where(x => peerId == x.id).ToArray()) 
                {
                    ForgetPeer(peer);
                }
            }

            public void ForgetAllPeers() 
            {
                foreach (RemotePeer peer in peers.ToArray()) 
                { 
                    ForgetPeer(peer);
                }
            }

    }
}