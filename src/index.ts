import { ethers, utils } from 'ethers'
import { maxUsers, maxAttesters, numEpochKeyNoncePerEpoch, epochLength, attestingFee, maxReputationBudget } from '../config'

import Unirep from "../artifacts/contracts/Unirep.sol/Unirep.json"
import EpochKeyValidityVerifier from "../artifacts/contracts/EpochKeyValidityVerifier.sol/EpochKeyValidityVerifier.json"
import ReputationVerifier from "../artifacts/contracts/ReputationVerifier.sol/ReputationVerifier.json"
import UserSignUpVerifier from "../artifacts/contracts/UserSignUpVerifier.sol/UserSignUpVerifier.json"
import StartTransitionVerifier from "../artifacts/contracts/StartTransitionVerifier.sol/StartTransitionVerifier.json"
import UserStateTransitionVerifier from "../artifacts/contracts/UserStateTransitionVerifier.sol/UserStateTransitionVerifier.json"
import ProcessAttestationsVerifier from "../artifacts/contracts/ProcessAttestationsVerifier.sol/ProcessAttestationsVerifier.json"

import PoseidonT3 from "../artifacts/contracts/Poseidon.sol/PoseidonT3.json"
import PoseidonT6 from "../artifacts/contracts/Poseidon.sol/PoseidonT6.json"

const linkLibraries = (
    {
      bytecode,
      linkReferences,
    }: {
      bytecode: string
      linkReferences: { [fileName: string]: { [contractName: string]: { length: number; start: number }[] } }
    },
    libraries: { [libraryName: string]: string }
  ): string => {
    Object.keys(linkReferences).forEach((fileName) => {
      Object.keys(linkReferences[fileName]).forEach((contractName) => {
        if (!libraries.hasOwnProperty(contractName)) {
          throw new Error(`Missing link library name ${contractName}`)
        }
        const address = utils.getAddress(libraries[contractName]).toLowerCase().slice(2)
        linkReferences[fileName][contractName].forEach(({ start: byteStart, length: byteLength }) => {
          const start = 2 + byteStart * 2
          const length = byteLength * 2
          bytecode = bytecode
            .slice(0, start)
            .concat(address)
            .concat(bytecode.slice(start + length, bytecode.length))
        })
      })
    })
    return bytecode
  }

const deployUnirep = async (
    deployer: ethers.Signer,
    _treeDepths: any,
    _settings?: any): Promise<ethers.Contract> => {
    let PoseidonT3Contract, PoseidonT6Contract
    let EpochKeyValidityVerifierContract, StartTransitionVerifierContract, ProcessAttestationsVerifierContract, UserStateTransitionVerifierContract, ReputationVerifierContract, UserSignUpVerifierContract

    console.log('Deploying PoseidonT3')
    const PoseidonT3Factory = new ethers.ContractFactory(PoseidonT3.abi, PoseidonT3.bytecode, deployer)
    PoseidonT3Contract = await PoseidonT3Factory.deploy()
    await PoseidonT3Contract.deployTransaction.wait()
    
    console.log('Deploying PoseidonT6')
    const PoseidonT6Factory = new ethers.ContractFactory(PoseidonT6.abi, PoseidonT6.bytecode, deployer)
    PoseidonT6Contract = await PoseidonT6Factory.deploy()
    await PoseidonT6Contract.deployTransaction.wait()

    console.log('Deploying EpochKeyValidityVerifier')
    const EpochKeyValidityVerifierFactory = new ethers.ContractFactory(EpochKeyValidityVerifier.abi, EpochKeyValidityVerifier.bytecode, deployer)
    EpochKeyValidityVerifierContract = await EpochKeyValidityVerifierFactory.deploy()
    await EpochKeyValidityVerifierContract.deployTransaction.wait()

    console.log('Deploying StartTransitionVerifier')
    const StartTransitionVerifierFactory = new ethers.ContractFactory(StartTransitionVerifier.abi, StartTransitionVerifier.bytecode, deployer)
    StartTransitionVerifierContract = await StartTransitionVerifierFactory.deploy()
    await StartTransitionVerifierContract.deployTransaction.wait()

    console.log('Deploying ProcessAttestationsVerifier')
    const ProcessAttestationsVerifierFactory = new ethers.ContractFactory(ProcessAttestationsVerifier.abi, ProcessAttestationsVerifier.bytecode, deployer)
    ProcessAttestationsVerifierContract = await ProcessAttestationsVerifierFactory.deploy()
    await ProcessAttestationsVerifierContract.deployTransaction.wait()

    console.log('Deploying UserStateTransitionVerifier')
    const UserStateTransitionVerifierFactory = new ethers.ContractFactory(UserStateTransitionVerifier.abi, UserStateTransitionVerifier.bytecode, deployer)
    UserStateTransitionVerifierContract = await UserStateTransitionVerifierFactory.deploy()
    await UserStateTransitionVerifierContract.deployTransaction.wait()

    console.log('Deploying ReputationVerifier')
    const  ReputationVerifierFactory = new ethers.ContractFactory(ReputationVerifier.abi,  ReputationVerifier.bytecode, deployer)
    ReputationVerifierContract = await ReputationVerifierFactory.deploy()
    await ReputationVerifierContract.deployTransaction.wait()

    console.log('Deploying UserSignUpVerifier')
    const  UserSignUpVerifierFactory = new ethers.ContractFactory(UserSignUpVerifier.abi,  UserSignUpVerifier.bytecode, deployer)
    UserSignUpVerifierContract = await UserSignUpVerifierFactory.deploy()
    await UserSignUpVerifierContract.deployTransaction.wait()

    console.log('Deploying Unirep')
    let _maxUsers, _maxAttesters, _numEpochKeyNoncePerEpoch, _maxReputationBudget, _epochLength, _attestingFee
    if (_settings) {
        _maxUsers = _settings.maxUsers
        _maxAttesters = _settings.maxAttesters,
        _numEpochKeyNoncePerEpoch = _settings.numEpochKeyNoncePerEpoch
        _maxReputationBudget = _settings.maxReputationBudget
        _epochLength = _settings.epochLength
        _attestingFee = _settings.attestingFee
    } else {
        _maxUsers = maxUsers
        _maxAttesters = maxAttesters
        _numEpochKeyNoncePerEpoch = numEpochKeyNoncePerEpoch
        _maxReputationBudget = maxReputationBudget,
        _epochLength = epochLength
        _attestingFee = attestingFee
    }

    // Link libraries
    const bytecode = linkLibraries({
        'bytecode': Unirep.bytecode,
        'linkReferences': Unirep.linkReferences
    }, {
        "PoseidonT3": PoseidonT3Contract.address,
        "PoseidonT6": PoseidonT6Contract.address
    })
    const f = new ethers.ContractFactory(Unirep.abi, bytecode, deployer)
    const c = await f.deploy(
        _treeDepths,
        {
            "maxUsers": _maxUsers,
            "maxAttesters": _maxAttesters,
        },
        EpochKeyValidityVerifierContract.address,
        StartTransitionVerifierContract.address,
        ProcessAttestationsVerifierContract.address,
        UserStateTransitionVerifierContract.address,
        ReputationVerifierContract.address,
        UserSignUpVerifierContract.address,
        _numEpochKeyNoncePerEpoch,
        _maxReputationBudget,
        _epochLength,
        _attestingFee,
        {
        gasLimit: 9000000,
    })
    await c.deployTransaction.wait()

    // Print out deployment info
    console.log("-----------------------------------------------------------------")
    console.log("Bytecode size of Unirep:", Math.floor(Unirep.bytecode.length / 2), "bytes")
    let receipt = await c.provider.getTransactionReceipt(c.deployTransaction.hash)
    console.log("Gas cost of deploying Unirep:", receipt.gasUsed.toString())
    console.log("-----------------------------------------------------------------")

    return c
}

const getUnirepContract = (addressOrName: string, signerOrProvider: ethers.Signer | ethers.providers.Provider | undefined) => {
    return new ethers.Contract(
        addressOrName,
        Unirep.abi,
        signerOrProvider,
    )
}

export {
    deployUnirep,
    getUnirepContract,
}