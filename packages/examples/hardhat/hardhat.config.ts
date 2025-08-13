// Minimal Hardhat config with networks only
import { HardhatUserConfig } from "hardhat/config";

const config: HardhatUserConfig = {
  solidity: "0.8.24",
  networks: {
    sepolia: {
      url: process.env.RPC_SEPOLIA || "",
    },
  },
};

export default config;


