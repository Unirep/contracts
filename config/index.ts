import { ethers } from 'ethers'

const attestingFee = ethers.utils.parseEther("0.01")

const numEpochKeyNoncePerEpoch = 3;

const numAttestationsPerProof = 5;

const epochLength = 30;  // 30 seconds


const circuitGlobalStateTreeDepth = 4;

const circuitUserStateTreeDepth = 4;

const circuitEpochTreeDepth = 32;

const circuitNullifierTreeDepth = 128;

const globalStateTreeDepth = circuitGlobalStateTreeDepth;

const userStateTreeDepth = circuitUserStateTreeDepth;

const epochTreeDepth = circuitEpochTreeDepth;

const nullifierTreeDepth = circuitNullifierTreeDepth;

const maxReputationBudget = 10;

const maxUsers = 2 ** circuitGlobalStateTreeDepth - 1;

export {
    attestingFee,
    circuitGlobalStateTreeDepth,
    circuitUserStateTreeDepth,
    circuitEpochTreeDepth,
    circuitNullifierTreeDepth,
    epochLength,
    epochTreeDepth,
    globalStateTreeDepth,
    numEpochKeyNoncePerEpoch,
    numAttestationsPerProof,
    maxUsers,
    nullifierTreeDepth,
    userStateTreeDepth,
    maxReputationBudget,
}