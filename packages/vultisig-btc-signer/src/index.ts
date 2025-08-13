import net from "node:net";

export class VultisigSigner {
  constructor(private socketPath: string = "/tmp/vultisig.sock") {}

  async signPsbt(psbtBase64: string): Promise<{ signedPsbtBase64?: string; finalTxHex?: string }> {
    const res = await request(this.socketPath, {
      id: 1,
      method: "sign",
      params: { scheme: "ecdsa", curve: "secp256k1", network: "btc", messageType: "btc_psbt", payload: { psbtBase64 } },
    });
    if (!res.result) throw new Error("bad response");
    return { signedPsbtBase64: res.result.raw };
  }
}

function request(socketPath: string, payload: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: socketPath }, () => {
      client.write(JSON.stringify(payload) + "\n");
    });
    let buffer = "";
    client.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        try { resolve(JSON.parse(line)); } catch (e) { reject(e); } finally { client.end(); }
      }
    });
    client.on("error", (err) => reject(err));
  });
}



