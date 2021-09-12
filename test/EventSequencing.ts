import { ethers as hardhatEthers } from 'hardhat'
import { ethers } from 'ethers'
import { expect } from "chai"
import { genRandomSalt, genIdentity, genIdentityCommitment } from '@unirep/crypto'

import { attestingFee, epochLength, numEpochKeyNoncePerEpoch } from '../config'
import { genEpochKey, getTreeDepthsForTesting, Attestation } from './utils'
import { deployUnirep } from '../src'
import Unirep from "../artifacts/contracts/Unirep.sol/Unirep.json"


describe('EventSequencing', () => {
    const events = ["UserSignUp", "AttestationSubmitted", "EpochEnded", "UserStateTransitioned"]
    let expectedEventsInOrder: string[] = []

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
        expectedEventsInOrder.push(events[0])

        // Attester sign up, no events emitted
        attester = accounts[1]
        attesterAddress = await attester.getAddress()
        unirepContractCalledByAttester = await hardhatEthers.getContractAt(Unirep.abi, unirepContract.address, attester)
        tx = await unirepContractCalledByAttester.attesterSignUp()
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        attesterId = await unirepContract.attesters(attesterAddress)

        // 2. Attest to first user
        let currentEpoch = await unirepContract.currentEpoch()
        let epochKeyNonce = 0
        let epochKey = genEpochKey(userIds[0].identityNullifier, currentEpoch.toNumber(), epochKeyNonce)
        let attestation: Attestation = new Attestation(
            BigInt(attesterId),
            BigInt(1),
            BigInt(0),
            genRandomSalt(),
        )
        tx = await unirepContractCalledByAttester.submitAttestation(
            attestation,
            epochKey,
            {value: attestingFee}
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(events[1])

        // 3. Second user sign up
        userId = genIdentity()
        userCommitment = genIdentityCommitment(userId)
        userIds.push(userId)
        userCommitments.push(userCommitment)
        tx = await unirepContract.userSignUp(userCommitment)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(events[0])

        // 4. First epoch end
        let numEpochKey = await unirepContract.getNumEpochKey(currentEpoch)
        expect(numEpochKey).equal(1)
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])  // Fast-forward epochLength of seconds
        tx = await unirepContract.beginEpochTransition(numEpochKey)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        currentEpoch = await unirepContract.currentEpoch()
        expectedEventsInOrder.push(events[2])

        // 5. Second user transition
        let transitionFromEpoch = 1
        const epkNullifiers: BigInt[] = []
        for (let i = 0; i < numEpochKeyNoncePerEpoch; i++) {
            epkNullifiers.push(BigInt(255))
        }
        const proof: BigInt[] = []
        for (let i = 0; i < 8; i++) {
            proof.push(BigInt(0))
        }
        // start user state transition proof

        // process attestation proofs

        // update user state root proof
        // tx = await unirepContract.updateUserStateRoot(
        //     genRandomSalt(),
        //     epkNullifiers,
        //     blindedUserStates,
        //     blindedHashChains,
        //     transitionFromEpoch,
        //     genRandomSalt(),
        //     genRandomSalt(),
        //     proof,
        // )
        // receipt = await tx.wait()
        // expect(receipt.status).equal(1)
        // expectedEventsInOrder.push(events[3])

        // 6. Attest to second user
        epochKeyNonce = 0
        epochKey = genEpochKey(userIds[1].identityNullifier, currentEpoch.toNumber(), epochKeyNonce)
        attestation = new Attestation(
            BigInt(attesterId),
            BigInt(2),
            BigInt(1),
            genRandomSalt(),
        )
        tx = await unirepContractCalledByAttester.submitAttestation(
            attestation,
            epochKey,
            {value: attestingFee}
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        expectedEventsInOrder.push(events[1])

        // 7. Second epoch end
        numEpochKey = await unirepContract.getNumEpochKey(currentEpoch)
        expect(numEpochKey).equal(1)
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])  // Fast-forward epochLength of seconds
        tx = await unirepContract.beginEpochTransition(numEpochKey)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        currentEpoch = await unirepContract.currentEpoch()
        expectedEventsInOrder.push(events[2])

        // 8. Third epoch end
        numEpochKey = await unirepContract.getNumEpochKey(currentEpoch)
        expect(numEpochKey).equal(0)
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])  // Fast-forward epochLength of seconds
        tx = await unirepContract.beginEpochTransition(numEpochKey)
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        currentEpoch = await unirepContract.currentEpoch()
        expectedEventsInOrder.push(events[2])

        // 9. First user transition
        transitionFromEpoch = 1
        // update user state root proof
        // tx = await unirepContract.updateUserStateRoot(
        //     genRandomSalt(),
        //     epkNullifiers,
        //     blindedUserStates,
        //     blindedHashChains,
        //     transitionFromEpoch,
        //     genRandomSalt(),
        //     genRandomSalt(),
        //     proof,
        // )
        // receipt = await tx.wait()
        // expect(receipt.status).equal(1)
        // expectedEventsInOrder.push(events[3])

        // 10. Second user transition
        transitionFromEpoch = 2
        // update user state root proof
        // tx = await unirepContract.updateUserStateRoot(
        //     genRandomSalt(),
        //     epkNullifiers,
        //     blindedUserStates,
        //     blindedHashChains,
        //     transitionFromEpoch,
        //     genRandomSalt(),
        //     genRandomSalt(),
        //     proof,
        // )
        // receipt = await tx.wait()
        // expect(receipt.status).equal(1)
        // expectedEventsInOrder.push(events[3])
    })

    it('Events order should match sequencer order', async () => {
        const sequencerFilter = unirepContract.filters.Sequencer()
        const sequencerEvents =  await unirepContract.queryFilter(sequencerFilter)
        expect(sequencerEvents.length).to.be.equal(7)

        for (let i = 0; i < sequencerEvents.length; i++) {
            const event = sequencerEvents[i]
            expect(event.args._event).equal(expectedEventsInOrder[i])
        }
    })
})