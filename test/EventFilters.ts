import { ethers as hardhatEthers } from 'hardhat'
import { ethers } from 'ethers'
import { expect } from "chai"
import { genRandomSalt, SNARK_FIELD_SIZE, genIdentity, genIdentityCommitment } from '@unirep/crypto'

import { attestingFee, epochLength, maxAttesters, maxReputationBudget, maxUsers, numEpochKeyNoncePerEpoch } from '../config'
import { genEpochKey, getTreeDepthsForTesting, Attestation, computeEpochKeyProofHash } from './utils'
import { deployUnirep } from '../src'

describe('Attesting', () => {
    let unirepContract

    let accounts: ethers.Signer[]

    let userId, userCommitment

    let attester, attesterAddress, attesterId, unirepContractCalledByAttester
    let attester2, attester2Address, unirepContractCalledByAttester2

    const signedUpInLeaf = 1
    const transitionFromEpoch = 1
    const proof: BigInt[] = []
    const reputationNullifiers: BigInt[] = []
    const epkNullifiers: BigInt[] = []
    const blindedHashChains: BigInt[] = []
    const blindedUserStates: BigInt[] = []
    const indexes: BigInt[] = []
    for (let i = 0; i < 8; i++) {
        proof.push(BigInt(0))
    }
    for (let i = 0; i < maxReputationBudget; i++) {
        reputationNullifiers.push(BigInt(255))
    }
    for (let i = 0; i < numEpochKeyNoncePerEpoch; i++) {
        epkNullifiers.push(BigInt(255))
        blindedHashChains.push(BigInt(255))
    }
    for (let i = 0; i < 2; i++) {
        blindedUserStates.push(BigInt(255))
    }
    const epoch = 1
    const nonce = 0
    const epochKey = genEpochKey(genRandomSalt(), epoch, nonce)
    const epochKeyProof = [genRandomSalt(), epoch, epochKey, proof]
    const signUpFlag = 0
    let epochKeyProofIndex

    before(async () => {
        accounts = await hardhatEthers.getSigners()

        const _treeDepths = getTreeDepthsForTesting()
        const _settings = {
            maxUsers: maxUsers,
            maxAttesters: maxAttesters,
            numEpochKeyNoncePerEpoch: numEpochKeyNoncePerEpoch,
            maxReputationBudget: maxReputationBudget,
            epochLength: epochLength,
            attestingFee: attestingFee
        }
        unirepContract = await deployUnirep(<ethers.Wallet>accounts[0], _treeDepths, _settings)

        console.log('User sign up')
        userId = genIdentity()
        userCommitment = genIdentityCommitment(userId)
        let tx = await unirepContract.userSignUp(userCommitment)
        let receipt = await tx.wait()
        expect(receipt.status).equal(1)

        console.log('Attesters sign up')
        attester = accounts[1]
        attesterAddress = await attester.getAddress()
        unirepContractCalledByAttester = unirepContract.connect(attester)
        tx = await unirepContractCalledByAttester.attesterSignUp()
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        attesterId = await unirepContract.attesters(attesterAddress)
        // Sign up another attester
        attester2 = accounts[2]
        attester2Address = await attester2.getAddress()
        unirepContractCalledByAttester2 = unirepContract.connect(attester2)
        tx = await unirepContractCalledByAttester2.attesterSignUp()
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
    })

    it('submit an epoch key proof should succeed', async () => {
        const tx = await unirepContract.submitEpochKeyProof(epochKeyProof)
        const receipt = await tx.wait()
        expect(receipt.status).equal(1)

        const proofNullifier = await unirepContract.hashEpochKeyProof(epochKeyProof)
        expect(receipt.status).equal(1)
        const _proofNullifier = computeEpochKeyProofHash(epochKeyProof)
        expect(_proofNullifier).equal(proofNullifier)
        epochKeyProofIndex = await unirepContract.getProofIndex(proofNullifier)
        expect(epochKeyProof).not.equal(null)
    })

    it('submit attestation should succeed', async () => {
        let attestation: Attestation = new Attestation(
            BigInt(attesterId),
            BigInt(1),
            BigInt(0),
            genRandomSalt(),
            BigInt(signedUpInLeaf),
        )
        
        const tx = await unirepContractCalledByAttester.submitAttestation(
            attestation,
            epochKey,
            epochKeyProofIndex,
            {value: attestingFee}
        )
        const receipt = await tx.wait()
        expect(receipt.status).equal(1)
    })

    it('spend reputation should succeed', async () => {
        const reputationProofData = [
            reputationNullifiers,
            epoch,
            epochKey,
            genRandomSalt(),
            attesterId,
            maxReputationBudget,
            0,
            0,
            genRandomSalt(),
            proof
        ]
        const tx = await unirepContractCalledByAttester.spendReputation(
            reputationProofData,
            {value: attestingFee},
        )
        const receipt = await tx.wait()
        expect(receipt.status).equal(1)

        const proofNullifier = await unirepContract.hashReputationProof(reputationProofData)
        expect(receipt.status).equal(1)
        epochKeyProofIndex = await unirepContract.getProofIndex(proofNullifier)
        expect(epochKeyProof).not.equal(null)
    })

    it('submit get airdrop should succeed', async () => {
        const userSignUpProof = [epoch, epochKey, genRandomSalt(), attesterId, signUpFlag, proof]
        
        let tx = await unirepContractCalledByAttester.airdropEpochKey(userSignUpProof, {value: attestingFee})
        const receipt = await tx.wait()
        expect(receipt.status).equal(1)

        const proofNullifier = await unirepContract.hashSignUpProof(userSignUpProof)
        expect(receipt.status).equal(1)
        epochKeyProofIndex = await unirepContract.getProofIndex(proofNullifier)
        expect(epochKeyProof).not.equal(null)
    })

    it('submit start user state transition should success', async () => {
        const blindedUserState = genRandomSalt()
        const blindedHashChain = genRandomSalt()
        const globalStateTree = genRandomSalt()
        const tx = await unirepContract.startUserStateTransition(
            blindedUserState,
            blindedHashChain,
            globalStateTree,
            proof,
        )
        const receipt = await tx.wait()
        expect(receipt.status).equal(1)

        const proofNullifier = await unirepContract.hashStartTransitionProof(blindedUserState, blindedHashChain, globalStateTree, proof,)
        expect(receipt.status).equal(1)
        epochKeyProofIndex = await unirepContract.getProofIndex(proofNullifier)
        expect(epochKeyProof).not.equal(null)
    })

    it('submit process attestation proofs should success', async () => {
        const outputBlindedUserState = genRandomSalt()
        const outputBlindedHashChain = genRandomSalt()
        const inputBlindedUserState = genRandomSalt()
        const tx = await unirepContract.processAttestations(
            outputBlindedUserState,
            outputBlindedHashChain,
            inputBlindedUserState,
            proof,
        )
        const receipt = await tx.wait()
        expect(receipt.status).equal(1)

        const proofNullifier = await unirepContract.hashProcessAttestationsProof(outputBlindedUserState, outputBlindedHashChain, inputBlindedUserState, proof,)
        expect(receipt.status).equal(1)
        epochKeyProofIndex = await unirepContract.getProofIndex(proofNullifier)
        expect(epochKeyProof).not.equal(null)
    })

    it('submit user state transition proofs should success', async () => {
        // Fast-forward epochLength of seconds
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])
        // Begin epoch transition
        let tx = await unirepContract.beginEpochTransition()
        let receipt = await tx.wait()
        expect(receipt.status).equal(1)
        
        const userStateTransitionData = [
            genRandomSalt(),
            epkNullifiers,
            transitionFromEpoch,
            blindedUserStates,
            genRandomSalt(),
            blindedHashChains,
            genRandomSalt(),
            proof,
        ]
        tx = await unirepContract.updateUserStateRoot(userStateTransitionData, indexes)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)

        const proofNullifier = await unirepContract.hashUserStateTransitionProof(userStateTransitionData)
        expect(receipt.status).equal(1)
        epochKeyProofIndex = await unirepContract.getProofIndex(proofNullifier)
        expect(epochKeyProof).not.equal(null)
    })

    it('submit attestation events should match and correctly emitted', async () => {
        const attestationSubmittedFilter = unirepContract.filters.AttestationSubmitted()
        const attestationSubmittedEvents =  await unirepContract.queryFilter(attestationSubmittedFilter)

        // compute hash chain of valid epoch key
        for (let i = 0; i < attestationSubmittedEvents.length; i++) {
            const proofIndex = attestationSubmittedEvents[i].args?._proofIndex
            const epochKeyProofFilter = unirepContract.filters.EpochKeyProof(proofIndex)
            const epochKeyProofEvent = await unirepContract.queryFilter(epochKeyProofFilter)
            const repProofFilter = unirepContract.filters.ReputationNullifierProof(proofIndex)
            const repProofEvent = await unirepContract.queryFilter(repProofFilter)
            const signUpProofFilter = unirepContract.filters.UserSignedUpProof(proofIndex)
            const signUpProofEvent = await unirepContract.queryFilter(signUpProofFilter)

            if (epochKeyProofEvent.length == 1){
                console.log('epoch key proof event')
                const args = epochKeyProofEvent[0]?.args?.epochKeyProofData
                expect(args?.globalStateTree).to.equal(epochKeyProof[0])
                expect(args?.epoch).to.equal(epochKeyProof[1])
                expect(args?.epochKey).to.equal(epochKeyProof[2])
                expect(args?.proof.length).to.equal(proof.length)
                const isValid = await unirepContract.verifyEpochKeyValidity(
                    args?.globalStateTree,
                    args?.epoch,
                    args?.epochKey,
                    args?.proof
                )
                // should not be reverted with invalid input
            } else if (repProofEvent.length == 1){
                console.log('reputation proof event')
                const args = repProofEvent[0]?.args?.reputationProofData
                expect(args?.repNullifiers.length).to.equal(maxReputationBudget)
                expect(args?.proof.length).to.equal(proof.length)
                const isValid = await unirepContract.verifyReputation(
                    args?.repNullifiers,
                    args?.epoch,
                    args?.epochKey,
                    args?.globalStateTree,
                    args?.attesterId,
                    args?.proveReputationAmount,
                    args?.minRep,
                    args?.proveGraffiti,
                    args?.graffitiPreImage,
                    args?.proof,
                )
                // should not be reverted with invalid input
            } else if (signUpProofEvent.length == 1){
                console.log('sign up proof event')
                const args = signUpProofEvent[0]?.args?.signUpProofData
                expect(args?.proof.length).to.equal(proof.length)
                const isValid = await unirepContract.verifyUserSignUp(
                    args?.epoch,
                    args?.epochKey,
                    args?.globalStateTree,
                    args?.attesterId,
                    args?.userHasSignedUp,
                    args?.proof,
                )
                // should not be reverted with invalid input
            }
        }
    })

    it('user state transition proof should match and correctly emitted', async () => {
        const startTransitionFilter = unirepContract.filters.StartedTransitionProof()
        const startTransitionEvents =  await unirepContract.queryFilter(startTransitionFilter)
        expect(startTransitionEvents.length).to.equal(1)
        expect(startTransitionEvents[0]?.args?._proof?.length).to.equal(proof.length)
        let isValid = await unirepContract.verifyStartTransitionProof(
            startTransitionEvents[0]?.args?._blindedUserState,
            startTransitionEvents[0]?.args?._blindedHashChain,
            startTransitionEvents[0]?.args?._globalStateTree,
            startTransitionEvents[0]?.args?._proof,
        )
        // should not be reverted with invalid input

        const processAttestationFilter = unirepContract.filters.ProcessedAttestationsProof()
        const processAttestationEvents = await unirepContract.queryFilter(processAttestationFilter)
        expect(processAttestationEvents.length).to.equal(1)
        expect(processAttestationEvents[0]?.args?._proof?.length).to.equal(proof.length)
        isValid = await unirepContract.verifyProcessAttestationProof(
            processAttestationEvents[0]?.args?._outputBlindedUserState,
            processAttestationEvents[0]?.args?._outputBlindedHashChain,
            processAttestationEvents[0]?.args?._inputBlindedUserState,
            processAttestationEvents[0]?.args?._proof,
        )
        // should not be reverted with invalid input

        const userStateTransitionFilter = unirepContract.filters.UserStateTransitionProof()
        const userStateTransitionEvents = await unirepContract.queryFilter(userStateTransitionFilter)
        expect(userStateTransitionEvents.length).to.equal(1)
        const args = userStateTransitionEvents[0]?.args?.userTransitionedData
        expect(args?.proof.length).to.equal(proof.length)
        expect(args?.epkNullifiers.length).to.equal(numEpochKeyNoncePerEpoch)
        expect(args?.blindedUserStates.length).to.equal(2)
        expect(args?.blindedHashChains.length).to.equal(numEpochKeyNoncePerEpoch)
        isValid = await unirepContract.verifyUserStateTransition(
            args?.newGlobalStateTreeLeaf,
            args?.epkNullifiers,
            args?.transitionFromEpoch,
            args?.blindedUserStates,
            args?.fromGlobalStateTree,
            args?.blindedHashChains,
            args?.fromEpochTree,
            args?.proof,
        )
        // should not be reverted with invalid input
    })
})