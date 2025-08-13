import { JsonRpcProvider } from "ethers";
import { VultisigSigner } from "vultisig-eth-signer";

async function main() {
  const rpc = process.env.RPC_SEPOLIA;
  if (!rpc) throw new Error("RPC_SEPOLIA not set");
  const socket = process.env.VULTISIG_SOCKET || "/tmp/vultisig.sock";

  const provider = new JsonRpcProvider(rpc);
  const signer = new VultisigSigner(provider, socket);

  const address = await signer.getAddress();
  console.log("Signer address:", address);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});


