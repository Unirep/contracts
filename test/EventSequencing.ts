// @ts-ignore
import { ethers as hardhatEthers } from 'hardhat'
import { ethers } from 'ethers'
import { expect } from "chai"
import { genRandomSalt, genIdentity, genIdentityCommitment } from '@unirep/crypto'
import { attestingFee, epochLength, maxReputationBudget, numEpochKeyNoncePerEpoch } from '../config'
import { genEpochKey, getTreeDepthsForTesting, Attestation, computeEpochKeyProofHash } from './utils'
import { deployUnirep, Event, Unirep } from '../src'

describe('EventSequencing', () => {
    let expectedEventsInOrder: Event[] = []
    let expectedEventsNumber: number = 0

    let unirepContract

    let accounts: ethers.Signer[]

    let userIds: any[] = [], userCommitments: any[] = []

    let attester, attesterAddress, attesterId, unirepContractCalledByAttester

    before(async () => {
        accounts = await hardhatEthers.getSigners()

        const _treeDepths = getTreeDepthsForTesting()
        unirepContract = await deployUnirep(<ethers.Wallet>accounts[0], _treeDepths)

        // 1. Fisrt user sign up
        let userId = genIdentity()
        let userCommitment = genIdentityCommitment(userId)
        userIds.push(userId)
        userCommitments.push(userCommitment)
        let tx = await unirepContract.userSignUp(userCommitment)
        let receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(Event.UserSignedUp)
        expectedEventsNumber ++

        // Attester sign up, no events emitted
        attester = accounts[1]
        attesterAddress = await attester.getAddress()
        unirepContractCalledByAttester = await hardhatEthers.getContractAt(Unirep.abi, unirepContract.address, attester)
        tx = await unirepContractCalledByAttester.attesterSignUp()
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        attesterId = await unirepContract.attesters(attesterAddress)

        // 2. Submit epoch key proof
        let currentEpoch = await unirepContract.currentEpoch()
        let epochKeyNonce = 0
        let epochKey = genEpochKey(userIds[0].identityNullifier, currentEpoch.toNumber(), epochKeyNonce)
        const proof: BigInt[] = []
        for (let i = 0; i < 8; i++) {
            proof.push(BigInt(0))
        }
        let epochKeyProof = [genRandomSalt(), currentEpoch, epochKey, proof]
        tx = await unirepContract.submitEpochKeyProof(epochKeyProof)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        const proofNullifier = computeEpochKeyProofHash(epochKeyProof)
        const epochKeyProofIndex = await unirepContract.getProofIndex(proofNullifier)
        expect(epochKeyProof).not.equal(null)

        // 2. Submit reputation nullifiers
        const reputationNullifiers: BigInt[] = []
        const minRep = 0
        const proveGraffiti = 1
        for (let i = 0; i < maxReputationBudget; i++) {
            reputationNullifiers.push(BigInt(255))
        }
        tx = await unirepContractCalledByAttester.spendReputation([
            reputationNullifiers,
            currentEpoch.toNumber(),
            epochKey,
            genRandomSalt(),
            attesterId.toNumber(),
            0,
            minRep,
            proveGraffiti,
            genRandomSalt(),
            proof],
            {value: attestingFee}
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(Event.AttestationSubmitted)
        expectedEventsNumber ++

        // 3. Attest to first user
        const signedUpInLeaf = 0
        let attestation: Attestation = new Attestation(
            BigInt(attesterId),
            BigInt(1),
            BigInt(0),
            genRandomSalt(),
            BigInt(signedUpInLeaf),
        )
        tx = await unirepContractCalledByAttester.submitAttestation(
            attestation,
            epochKey,
            epochKeyProofIndex,
            {value: attestingFee}
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(Event.AttestationSubmitted)
        expectedEventsNumber ++

        // 4. Second user sign up
        userId = genIdentity()
        userCommitment = genIdentityCommitment(userId)
        userIds.push(userId)
        userCommitments.push(userCommitment)
        tx = await unirepContract.userSignUp(userCommitment)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(Event.UserSignedUp)
        expectedEventsNumber ++

        // 5. First epoch end
        // let numEpochKey = await unirepContract.getNumEpochKey(currentEpoch)
        // expect(numEpochKey).equal(1)
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])  // Fast-forward epochLength of seconds
        tx = await unirepContract.beginEpochTransition()
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        currentEpoch = await unirepContract.currentEpoch()
        expectedEventsInOrder.push(Event.EpochEnded)
        expectedEventsNumber ++

        // 6. Second user starts transition
        let transitionFromEpoch = 1
        const epkNullifiers: BigInt[] = []
        const blindedHashChains: BigInt[] = []
        const blindedUserStates: BigInt[] = []
        const indexes: BigInt[] = []
        for (let i = 0; i < numEpochKeyNoncePerEpoch; i++) {
            epkNullifiers.push(BigInt(255))
            blindedHashChains.push(BigInt(255))
        }
        for (let i = 0; i < 2; i++) {
            blindedUserStates.push(BigInt(255))
        }
        tx = await unirepContract.startUserStateTransition(
            genRandomSalt(),
            genRandomSalt(),
            genRandomSalt(),
            proof,
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)

        // 7. Second user processes attestations
        tx = await unirepContract.processAttestations(
            genRandomSalt(),
            genRandomSalt(),
            genRandomSalt(),
            proof,
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)

        // 8. Second user transition
        tx = await unirepContract.updateUserStateRoot([
            genRandomSalt(),
            epkNullifiers,
            transitionFromEpoch,
            blindedUserStates,
            genRandomSalt(),
            blindedHashChains,
            genRandomSalt(),
            proof,
        ], indexes)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(Event.UserStateTransitioned)
        expectedEventsNumber ++

        // 9. Attest to second user
        epochKeyNonce = 0
        epochKey = genEpochKey(userIds[1].identityNullifier, currentEpoch.toNumber(), epochKeyNonce)
        attestation = new Attestation(
            BigInt(attesterId),
            BigInt(2),
            BigInt(1),
            genRandomSalt(),
            BigInt(signedUpInLeaf),
        )
        epochKeyProof = [genRandomSalt(), currentEpoch, epochKey, proof]
        tx = await unirepContractCalledByAttester.submitAttestation(
            attestation,
            epochKey,
            epochKeyProofIndex,
            {value: attestingFee}
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(Event.AttestationSubmitted)
        expectedEventsNumber ++

        // 10. Second epoch end
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])  // Fast-forward epochLength of seconds
        tx = await unirepContract.beginEpochTransition()
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        currentEpoch = await unirepContract.currentEpoch()
        expectedEventsInOrder.push(Event.EpochEnded)
        expectedEventsNumber ++

        // 11. Third epoch end
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])  // Fast-forward epochLength of seconds
        tx = await unirepContract.beginEpochTransition()
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        currentEpoch = await unirepContract.currentEpoch()
        expectedEventsInOrder.push(Event.EpochEnded)
        expectedEventsNumber ++

        // 12. First user starts transition
        transitionFromEpoch = 1
        tx = await unirepContract.startUserStateTransition(
            genRandomSalt(),
            genRandomSalt(),
            genRandomSalt(),
            proof,
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)

        // 13. First user processes attestations
        tx = await unirepContract.processAttestations(
            genRandomSalt(),
            genRandomSalt(),
            genRandomSalt(),
            proof,
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)

        // 14. First user transition
        tx = await unirepContract.updateUserStateRoot([
            genRandomSalt(),
            epkNullifiers,
            transitionFromEpoch,
            blindedUserStates,
            genRandomSalt(),
            blindedHashChains,
            genRandomSalt(),
            proof,
        ], indexes)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(Event.UserStateTransitioned)
        expectedEventsNumber ++

        // 15. Second user starts transition
        transitionFromEpoch = 2
        tx = await unirepContract.startUserStateTransition(
            genRandomSalt(),
            genRandomSalt(),
            genRandomSalt(),
            proof,
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)

        // 16. Second user processes attestations
        epochKeyProof = [genRandomSalt(), currentEpoch, epochKey, proof]
        tx = await unirepContract.processAttestations(
            genRandomSalt(),
            genRandomSalt(),
            genRandomSalt(),
            proof,
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)

        // 17. Second user transition
        tx = await unirepContract.updateUserStateRoot([
            genRandomSalt(),
            epkNullifiers,
            transitionFromEpoch,
            blindedUserStates,
            genRandomSalt(),
            blindedHashChains,
            genRandomSalt(),
            proof,
        ], indexes)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(Event.UserStateTransitioned)
        expectedEventsNumber ++
    })

    it('Events order should match sequencer order', async () => {
        const sequencerFilter = unirepContract.filters.Sequencer()
        const sequencerEvents =  await unirepContract.queryFilter(sequencerFilter)
        expect(sequencerEvents.length).to.be.equal(expectedEventsNumber)

        for (let i = 0; i < sequencerEvents.length; i++) {
            const event = sequencerEvents[i]
            expect(event.args._event).equal(expectedEventsInOrder[i])
        }
    })
})