import { ethers } from 'ethers';
import Unirep from "../artifacts/contracts/Unirep.sol/Unirep.json";
declare const deployUnirep: (deployer: ethers.Signer, _treeDepths: any, _settings?: any) => Promise<ethers.Contract>;
declare const getUnirepContract: (addressOrName: string, signerOrProvider: ethers.Signer | ethers.providers.Provider | undefined) => ethers.Contract;
export { deployUnirep, getUnirepContract, Unirep };