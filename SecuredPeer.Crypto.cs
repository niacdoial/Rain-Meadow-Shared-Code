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
using LibSodium;

namespace RainMeadow.Shared
{
    public partial class SecuredPeerManager : BasePeerManager
    {
        void ResetKeys() {
            unsafe
            {
                fixed (byte* p_conn_sk = this.connection_sk; byte* p_conn_pk = this.connection_pk)
                {
                    int errCode = LibSodium.crypto_box_keypair(p_conn_pk, p_conn_sk);
                    if (errCode) {
                        throw new Exception("failed to generate connection keypair: errno "+errCode.ToString());
                    }
                }
                fixed (byte* p_id_sk = this.identity_sk; byte* p_id_pk = this.identity_pk)
                {
                    int errCode = LibSodium.crypto_sign_keypair(p_id_pk, p_id_sk);
                    if (errCode) {
                        throw new Exception("failed to generate identity keypair: errno "+errCode.ToString());
                    }
                }
            }
        }
    }
}
