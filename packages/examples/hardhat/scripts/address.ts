import "dotenv/config";
import { JsonRpcProvider } from "ethers";
import { VultisigSigner } from "vultisig-eth-signer";

async function main() {
  const provider = new JsonRpcProvider(process.env.RPC_SEPOLIA || "http://localhost:8545");
  const socket = process.env.VULTISIG_SOCKET || "/tmp/vultisig.sock";
  const signer = new VultisigSigner(provider, socket);
  console.log("Address:", await signer.getAddress());
}

main().catch((e) => (console.error(e), process.exit(1)));



