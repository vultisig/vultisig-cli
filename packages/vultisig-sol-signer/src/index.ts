import net from "node:net";

export class VultisigSigner {
  constructor(private socketPath: string = "/tmp/vultisig.sock") {}

  async getAddress(): Promise<string> {
    const res = await request(this.socketPath, {
      id: 1,
      method: "get_address",
      params: { scheme: "eddsa", curve: "ed25519", network: "sol" },
    });
    if (!res.result?.pubkey) throw new Error("bad response");
    return res.result.pubkey;
  }

  async sign(bytes: Uint8Array): Promise<string> {
    const res = await request(this.socketPath, {
      id: 2,
      method: "sign",
      params: { scheme: "eddsa", curve: "ed25519", network: "sol", messageType: "sol_tx", payload: { bytes: Buffer.from(bytes).toString("base64") } },
    });
    if (!res.result?.signature) throw new Error("bad response");
    return res.result.signature;
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



