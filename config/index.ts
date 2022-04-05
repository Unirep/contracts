import { circuitGlobalStateTreeDepth, circuitUserStateTreeDepth, circuitEpochTreeDepth } from '@unirep/circuits/config';
import { ethers } from 'ethers'

const attestingFee = ethers.utils.parseEther("0")

const numEpochKeyNoncePerEpoch = 3;

const numAttestationsPerProof = 5;

const epochLength = 30;  // 30 seconds


const globalStateTreeDepth = circuitGlobalStateTreeDepth;

const userStateTreeDepth = circuitUserStateTreeDepth;

const epochTreeDepth = circuitEpochTreeDepth;

const maxReputationBudget = 10;

const maxUsers = 2 ** circuitGlobalStateTreeDepth - 1;

const maxAttesters = 2 ** circuitUserStateTreeDepth - 1;

export {
    attestingFee,
    circuitGlobalStateTreeDepth,
    circuitUserStateTreeDepth,
    circuitEpochTreeDepth,
    epochLength,
    epochTreeDepth,
    globalStateTreeDepth,
    numEpochKeyNoncePerEpoch,
    numAttestationsPerProof,
    maxUsers,
    maxAttesters,
    userStateTreeDepth,
    maxReputationBudget,
}