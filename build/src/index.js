"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Unirep = exports.getUnirepContract = exports.deployUnirep = void 0;
const ethers_1 = require("ethers");
const config_1 = require("../config");
const Unirep_json_1 = __importDefault(require("../artifacts/contracts/Unirep.sol/Unirep.json"));
exports.Unirep = Unirep_json_1.default;
const EpochKeyValidityVerifier_json_1 = __importDefault(require("../artifacts/contracts/EpochKeyValidityVerifier.sol/EpochKeyValidityVerifier.json"));
const ReputationVerifier_json_1 = __importDefault(require("../artifacts/contracts/ReputationVerifier.sol/ReputationVerifier.json"));
const UserSignUpVerifier_json_1 = __importDefault(require("../artifacts/contracts/UserSignUpVerifier.sol/UserSignUpVerifier.json"));
const StartTransitionVerifier_json_1 = __importDefault(require("../artifacts/contracts/StartTransitionVerifier.sol/StartTransitionVerifier.json"));
const UserStateTransitionVerifier_json_1 = __importDefault(require("../artifacts/contracts/UserStateTransitionVerifier.sol/UserStateTransitionVerifier.json"));
const ProcessAttestationsVerifier_json_1 = __importDefault(require("../artifacts/contracts/ProcessAttestationsVerifier.sol/ProcessAttestationsVerifier.json"));
const PoseidonT3_json_1 = __importDefault(require("../artifacts/contracts/Poseidon.sol/PoseidonT3.json"));
const PoseidonT6_json_1 = __importDefault(require("../artifacts/contracts/Poseidon.sol/PoseidonT6.json"));
const linkLibraries = ({ bytecode, linkReferences, }, libraries) => {
    Object.keys(linkReferences).forEach((fileName) => {
        Object.keys(linkReferences[fileName]).forEach((contractName) => {
            if (!libraries.hasOwnProperty(contractName)) {
                throw new Error(`Missing link library name ${contractName}`);
            }
            const address = ethers_1.utils.getAddress(libraries[contractName]).toLowerCase().slice(2);
            linkReferences[fileName][contractName].forEach(({ start: byteStart, length: byteLength }) => {
                const start = 2 + byteStart * 2;
                const length = byteLength * 2;
                bytecode = bytecode
                    .slice(0, start)
                    .concat(address)
                    .concat(bytecode.slice(start + length, bytecode.length));
            });
        });
    });
    return bytecode;
};
const deployUnirep = async (deployer, _treeDepths, _settings) => {
    let PoseidonT3Contract, PoseidonT6Contract;
    let EpochKeyValidityVerifierContract, StartTransitionVerifierContract, ProcessAttestationsVerifierContract, UserStateTransitionVerifierContract, ReputationVerifierContract, UserSignUpVerifierContract;
    console.log('Deploying PoseidonT3');
    const PoseidonT3Factory = new ethers_1.ethers.ContractFactory(PoseidonT3_json_1.default.abi, PoseidonT3_json_1.default.bytecode, deployer);
    PoseidonT3Contract = await PoseidonT3Factory.deploy();
    await PoseidonT3Contract.deployTransaction.wait();
    console.log('Deploying PoseidonT6');
    const PoseidonT6Factory = new ethers_1.ethers.ContractFactory(PoseidonT6_json_1.default.abi, PoseidonT6_json_1.default.bytecode, deployer);
    PoseidonT6Contract = await PoseidonT6Factory.deploy();
    await PoseidonT6Contract.deployTransaction.wait();
    console.log('Deploying EpochKeyValidityVerifier');
    const EpochKeyValidityVerifierFactory = new ethers_1.ethers.ContractFactory(EpochKeyValidityVerifier_json_1.default.abi, EpochKeyValidityVerifier_json_1.default.bytecode, deployer);
    EpochKeyValidityVerifierContract = await EpochKeyValidityVerifierFactory.deploy();
    await EpochKeyValidityVerifierContract.deployTransaction.wait();
    console.log('Deploying StartTransitionVerifier');
    const StartTransitionVerifierFactory = new ethers_1.ethers.ContractFactory(StartTransitionVerifier_json_1.default.abi, StartTransitionVerifier_json_1.default.bytecode, deployer);
    StartTransitionVerifierContract = await StartTransitionVerifierFactory.deploy();
    await StartTransitionVerifierContract.deployTransaction.wait();
    console.log('Deploying ProcessAttestationsVerifier');
    const ProcessAttestationsVerifierFactory = new ethers_1.ethers.ContractFactory(ProcessAttestationsVerifier_json_1.default.abi, ProcessAttestationsVerifier_json_1.default.bytecode, deployer);
    ProcessAttestationsVerifierContract = await ProcessAttestationsVerifierFactory.deploy();
    await ProcessAttestationsVerifierContract.deployTransaction.wait();
    console.log('Deploying UserStateTransitionVerifier');
    const UserStateTransitionVerifierFactory = new ethers_1.ethers.ContractFactory(UserStateTransitionVerifier_json_1.default.abi, UserStateTransitionVerifier_json_1.default.bytecode, deployer);
    UserStateTransitionVerifierContract = await UserStateTransitionVerifierFactory.deploy();
    await UserStateTransitionVerifierContract.deployTransaction.wait();
    console.log('Deploying ReputationVerifier');
    const ReputationVerifierFactory = new ethers_1.ethers.ContractFactory(ReputationVerifier_json_1.default.abi, ReputationVerifier_json_1.default.bytecode, deployer);
    ReputationVerifierContract = await ReputationVerifierFactory.deploy();
    await ReputationVerifierContract.deployTransaction.wait();
    console.log('Deploying UserSignUpVerifier');
    const UserSignUpVerifierFactory = new ethers_1.ethers.ContractFactory(UserSignUpVerifier_json_1.default.abi, UserSignUpVerifier_json_1.default.bytecode, deployer);
    UserSignUpVerifierContract = await UserSignUpVerifierFactory.deploy();
    await UserSignUpVerifierContract.deployTransaction.wait();
    console.log('Deploying Unirep');
    let _maxUsers, _maxAttesters, _numEpochKeyNoncePerEpoch, _maxReputationBudget, _epochLength, _attestingFee;
    if (_settings) {
        _maxUsers = _settings.maxUsers;
        _maxAttesters = _settings.maxAttesters,
            _numEpochKeyNoncePerEpoch = _settings.numEpochKeyNoncePerEpoch;
        _maxReputationBudget = _settings.maxReputationBudget;
        _epochLength = _settings.epochLength;
        _attestingFee = _settings.attestingFee;
    }
    else {
        _maxUsers = config_1.maxUsers;
        _maxAttesters = config_1.maxAttesters;
        _numEpochKeyNoncePerEpoch = config_1.numEpochKeyNoncePerEpoch;
        _maxReputationBudget = config_1.maxReputationBudget,
            _epochLength = config_1.epochLength;
        _attestingFee = config_1.attestingFee;
    }
    // Link libraries
    const bytecode = linkLibraries({
        'bytecode': Unirep_json_1.default.bytecode,
        'linkReferences': Unirep_json_1.default.linkReferences
    }, {
        "PoseidonT3": PoseidonT3Contract.address,
        "PoseidonT6": PoseidonT6Contract.address
    });
    const f = new ethers_1.ethers.ContractFactory(Unirep_json_1.default.abi, bytecode, deployer);
    const c = await f.deploy(_treeDepths, {
        "maxUsers": _maxUsers,
        "maxAttesters": _maxAttesters,
    }, EpochKeyValidityVerifierContract.address, StartTransitionVerifierContract.address, ProcessAttestationsVerifierContract.address, UserStateTransitionVerifierContract.address, ReputationVerifierContract.address, UserSignUpVerifierContract.address, _numEpochKeyNoncePerEpoch, _maxReputationBudget, _epochLength, _attestingFee, {
        gasLimit: 9000000,
    });
    await c.deployTransaction.wait();
    // Print out deployment info
    console.log("-----------------------------------------------------------------");
    console.log("Bytecode size of Unirep:", Math.floor(Unirep_json_1.default.bytecode.length / 2), "bytes");
    let receipt = await c.provider.getTransactionReceipt(c.deployTransaction.hash);
    console.log("Gas cost of deploying Unirep:", receipt.gasUsed.toString());
    console.log("-----------------------------------------------------------------");
    return c;
};
exports.deployUnirep = deployUnirep;
const getUnirepContract = (addressOrName, signerOrProvider) => {
    return new ethers_1.ethers.Contract(addressOrName, Unirep_json_1.default.abi, signerOrProvider);
};
exports.getUnirepContract = getUnirepContract;
