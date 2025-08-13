import net from "node:net";
import { AbstractSigner, Provider, TransactionRequest, TypedDataDomain, TypedDataField, getAddress as toChecksumAddress } from "ethers";

type JsonRpcRequest = { id: number | string; method: string; params?: any };
type JsonRpcResponse = { id: number | string; result?: any; error?: any };

export class VultisigSigner extends AbstractSigner {
  private readonly socketPath: string;

  constructor(provider: Provider, socketPath: string = "/tmp/vultisig.sock") {
    super(provider);
    this.socketPath = socketPath;
  }

  connect(provider: Provider): VultisigSigner {
    return new VultisigSigner(provider, this.socketPath);
  }

  async getAddress(): Promise<string> {
    const res = await this.request({
      id: 1,
      method: "get_address",
      params: { scheme: "ecdsa", curve: "secp256k1", network: "eth" },
    });
    if (res.error) throw new Error(res.error?.message || "daemon error");
    if (!res.result || typeof res.result.address !== "string") {
      throw new Error(`bad response: ${JSON.stringify(res)}`);
    }
    return res.result.address;
  }

  async signTransaction(_tx: TransactionRequest): Promise<string> {
    const payload = canonicalizeTx(_tx);
    const res = await this.request({
      id: 2,
      method: "sign",
      params: {
        scheme: "ecdsa",
        curve: "secp256k1",
        network: "eth",
        messageType: "eth_tx",
        payload,
        policyContext: {},
      },
    });
    if (res.error) throw new Error(res.error?.message || "daemon error");
    const raw = res.result?.raw;
    if (typeof raw !== "string") throw new Error(`bad response: ${JSON.stringify(res)}`);
    return raw;
  }

  async signTypedData<_T extends Record<string, Array<TypedDataField>>>(
    _domain: TypedDataDomain,
    _types: _T,
    _value: Record<string, any>
  ): Promise<string> {
    const res = await this.request({
      id: 3,
      method: "sign",
      params: {
        scheme: "ecdsa",
        curve: "secp256k1",
        network: "eth",
        messageType: "eth_typed",
        payload: { domain: _domain, types: _types, message: _value },
        policyContext: {},
      },
    });
    if (res.error) throw new Error(res.error?.message || "daemon error");
    const sig = res.result?.signature;
    if (typeof sig !== "string") throw new Error(`bad response: ${JSON.stringify(res)}`);
    return sig;
  }

  async signMessage(_message: string | Uint8Array): Promise<string> {
    throw new Error("signMessage not implemented yet");
  }

  private request(msg: JsonRpcRequest): Promise<JsonRpcResponse> {
    return new Promise((resolve, reject) => {
      const client = net.createConnection({ path: this.socketPath }, () => {
        client.write(JSON.stringify(msg) + "\n");
      });

      let buffer = "";
      client.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        let idx;
        while ((idx = buffer.indexOf("\n")) !== -1) {
          const line = buffer.slice(0, idx).trim();
          buffer = buffer.slice(idx + 1);
          if (!line) continue;
          try {
            const obj = JSON.parse(line);
            resolve(obj);
          } catch (e) {
            reject(e);
          } finally {
            client.end();
          }
        }
      });

      client.on("error", (err) => reject(err));
    });
  }
}

export default VultisigSigner;

function canonicalizeTx(tx: TransactionRequest) {
  const toWeiString = (v: any): string | undefined => {
    if (v === undefined || v === null) return undefined;
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "number") return BigInt(v).toString();
    if (typeof v === "string") {
      if (v.startsWith("0x") || v.startsWith("0X")) return BigInt(v).toString();
      return v;
    }
    // ethers may pass a BN-like; try toString
    if (typeof (v as any).toString === "function") return (v as any).toString();
    throw new Error("unsupported numeric value");
  };

  const out: any = {
    to: tx.to ? toChecksumAddress(String(tx.to)) : undefined,
    data: tx.data ? String(tx.data) : undefined,
    value: toWeiString(tx.value) ?? "0",
    nonce: typeof tx.nonce === "number" ? tx.nonce : tx.nonce !== undefined ? Number(tx.nonce) : undefined,
    gasLimit: toWeiString((tx as any).gasLimit) ?? undefined,
    maxFeePerGas: toWeiString((tx as any).maxFeePerGas) ?? undefined,
    maxPriorityFeePerGas: toWeiString((tx as any).maxPriorityFeePerGas) ?? undefined,
    chainId: typeof tx.chainId === "number" ? tx.chainId : tx.chainId !== undefined ? Number(tx.chainId) : undefined,
    type: 2,
  };
  return out;
}


