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
    public partial class PeerManager : IDisposable
    {
        public PeerId GetSelf() {
            return new PeerId(
                new IPEndPoint(
                    PeerManager.getInterfaceAddresses()[0],
                    this.port
                ),
                this.connection_pk
            );
        }
        public PeerId[] GetBroadcastPeerIDs() {
            List<PeerId> broadcastables = new List<PeerId>();
            for (int broadcast_port = DEFAULT_PORT;
                broadcast_port < (FIND_PORT_ATTEMPTS + DEFAULT_PORT);
                broadcast_port++)
            {
                broadcastables.Add(PeerId.MakeClearText(new(IPAddress.Broadcast, broadcast_port)));
            }
            return broadcastables.ToArray();
        }

        public PeerId? GetPeerIdByName(string name) {
            var parts = name.Split('@');
            IPEndPoint? endPoint = null;
            byte[] pubKey = new byte[0];

            if (parts.Count() == 2) {
                if (parts[0].Length != 2*LibSodium.BOX_PK_SIZE) return null;
                endPoint = GetEndPointByName(parts[1]);
                if (endPoint is null) return null;
                pubKey = LibSodium.BoxPubKeyFromHex(parts[0]);
                return new PeerId(endPoint, pubKey);
            } else if (parts.Count() == 1) {
                if (!allowPeerCreationWithoutKey) return null;
                endPoint = GetEndPointByName(parts[0]);
                if (endPoint is null) return null;
                return PeerId.MakeUnknown(endPoint);
            } else {
                return null;
            }
        }

        PeerId GetIdFromEndpoint(IPEndPoint endPoint) {
            RemotePeer? peer = peers.FirstOrDefault(x => CompareIPEndpoints(x.id.endPoint, endPoint));
            if (peer == null) {
                return null;
            } else {
                return peer.id;
            }
        }

        public static string describePeerId(PeerId peerId, PeerId? serverEndPoint=null){
            if (peerId is null) {
                return "[PeerId is null for some reason]";
            }
            var pubkeyString = "[NULL]";
            if (peerId.boxPubkey != null) {
                pubkeyString = LibSodium.BoxPubKeyToHex(peerId.boxPubkey);
            }

            return String.Format(
                "[pubkey: {3}, IP: [is machine local: {0}, is network local: {1}, is devnull: {2}]]",
                peerId.isLoopback(),
                isEndpointLocal(peerId.endPoint),
                peerId.isBlackHole(),
                pubkeyString
            );
        }

        public string GetGenericInviteCode() {
            var invitecode = LibSodium.BoxPubKeyToHex(this.connection_pk);
            return $"{invitecode}@X.X.X.X:{this.port}";
        }

        /// the functions that (de)serialize multiple endpoints at once can deal with the sender seeing itself differently as everyone else.
        /// The functions that do not need a separate mechanism to deal with this.
        public void SerializePeerIDs(BinaryWriter writer, PeerId[] endPoints, PeerId addressedto, bool includeme = true) {
            // note that outside of Blackhole, only status:connected peerIds can be serialized
            var filteredPeerIDs = endPoints.Select(x => x)
                .Where(x=> x != null).ToArray();
            // TODO: eventually apply the encrypted-only restriction on blackhole IDs too, since they are blackhole-as-request-for-proxy
            var badIDs = filteredPeerIDs.Where(x => !(x.isBlackHole() || x.status == PeerId.PeerStatus.Connected)).ToArray();
            if (badIDs.Count()>0) {
                foreach (PeerId point in badIDs) {
                    SharedCodeLogger.Error("Bad ID: " + point.status.ToString() + " : " + describePeerId(point));
                }
                throw new Exception("Serialisation only allowed if all peers serialised have known pubkeys!");
            }
            if (addressedto is null) {return;}

            writer.Write(includeme);
            writer.Write((int)filteredPeerIDs.Length);
            foreach (PeerId point in filteredPeerIDs) {
                if (point == addressedto) {
                    SerializeIPEndPoint(writer, new IPEndPoint(IPAddress.Loopback, point.endPoint.Port));
                    continue;
                }
                SerializeIPEndPoint(writer, point.endPoint);
                if (!point.isBlackHole()) {
                    // TODO: eventually redo logic to include/not include pubkey in serialisation,
                    // because of blackhole-as-request-for-proxy PeerIDs
                    if (point.boxPubkey.Length != LibSodium.BOX_PK_SIZE) {
                        throw new Exception("bad pubkey length, something fucked up bad");
                    }
                    writer.Write(point.boxPubkey);
                }
            }
        }

        public PeerId[] DeserializePeerIDs(BinaryReader reader, PeerId sender) {
            if (sender is null) {throw new Exception("bad PeerId as sender");}

            bool includesender = reader.ReadBoolean();
            PeerId[] ret = new PeerId[reader.ReadInt32() + (includesender? 1 : 0)];
            int i = 0;
            if (includesender) {
                ret[i] = sender;
                ++i;
            }

            for (; i != ret.Length; i++) {
                IPEndPoint endPoint = DeserializeIPEndPoint(reader);
                if (CompareIPEndpoints(endPoint, new IPEndPoint(IPAddress.Loopback, this.port))) {
                    ret[i] = new PeerId(endPoint, this.connection_pk);
                } else if (CompareIPEndpoints(endPoint, ((PeerId)BlackHole).endPoint)) {
                    // TODO: eventually change this when we will want pubkeys transmitted in blackhole-as-request-for-proxy PeerIDs.
                    ret[i] = (PeerId)BlackHole;
                } else {
                    byte[] pubkey = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                    ret[i] = new PeerId(endPoint, pubkey);
                }
            }
            return ret.ToArray();
        }

        public void SerializePeerId(BinaryWriter writer, PeerId peerId) {
            if (peerId is null) {throw new Exception("bad PeerId to serialize");}
            if (peerId.status != PeerId.PeerStatus.Connected) {throw new Exception("cannot serialize peer with no pubkey");}
            PeerManager.SerializeIPEndPoint(writer, peerId.endPoint);
            if (peerId.boxPubkey.Length != LibSodium.BOX_PK_SIZE) {
                throw new Exception("bad pubkey length, something fucked up bad");
            }
            writer.Write(peerId.boxPubkey);
        }
        public PeerId DeserializePeerId(BinaryReader reader) {
            return new PeerId(
                PeerManager.DeserializeIPEndPoint(reader),
                reader.ReadBytes(LibSodium.BOX_PK_SIZE)
            );
        }
    }
}
