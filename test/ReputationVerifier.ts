import { ethers as hardhatEthers } from 'hardhat'
import { ethers } from 'ethers'
import { expect } from "chai"
import { genProofAndPublicSignals, verifyProof, formatProofForVerifierContract } from "@unirep/circuits"
import { genRandomSalt, hashLeftRight, genIdentity, genIdentityCommitment, IncrementalQuinTree,  stringifyBigInts, SparseMerkleTreeImpl, hashOne, } from "@unirep/crypto"
import { circuitEpochTreeDepth, circuitGlobalStateTreeDepth, maxReputationBudget, circuitUserStateTreeDepth } from "../config"
import { genEpochKey, genNewUserStateTree, getTreeDepthsForTesting, Reputation } from './utils'
import { deployUnirep } from '../src'
import Unirep from "../artifacts/contracts/Unirep.sol/Unirep.json"


describe('Verify reputation verifier', function () {
    this.timeout(30000)
    let unirepContract
    let accounts: ethers.Signer[]
    const epoch = 1
    const nonce = 1
    const user = genIdentity()
    const epochKey = genEpochKey(user['identityNullifier'], epoch, nonce, circuitEpochTreeDepth)
    const NUM_ATTESTERS = 10

    let GSTZERO_VALUE = 0, GSTree, GSTreeRoot, GSTreeProof
    let userStateTree: SparseMerkleTreeImpl, userStateRoot
    let hashedLeaf
    let attesterId
    let results

    let reputationRecords = {}
    const MIN_POS_REP = 20
    const MAX_NEG_REP = 10
    const repNullifiersAmount = 3
    const nonceStarter = 0
    const selectors: BigInt[] = []
    const nonceList: BigInt[] = []
    let minRep = MIN_POS_REP - MAX_NEG_REP
    const proveGraffiti = 1
    const signUp = 1

    before(async () => {
        accounts = await hardhatEthers.getSigners()

        const _treeDepths = getTreeDepthsForTesting()
        unirepContract = await deployUnirep(<ethers.Wallet>accounts[0], _treeDepths)
        // User state
        userStateTree = await genNewUserStateTree()

        // Bootstrap user state
        for (let i = 0; i < NUM_ATTESTERS; i++) {
            let attesterId = i + 1
            while (reputationRecords[attesterId] !== undefined) attesterId = Math.floor(Math.random() * (2 ** circuitUserStateTreeDepth))
            const graffitiPreImage = genRandomSalt()
            reputationRecords[attesterId] = new Reputation(
                BigInt(Math.floor(Math.random() * 100) + MIN_POS_REP),
                BigInt(Math.floor(Math.random() * MAX_NEG_REP)),
                hashOne(graffitiPreImage),
                BigInt(signUp)
            )
            reputationRecords[attesterId].addGraffitiPreImage(graffitiPreImage)
            await userStateTree.update(BigInt(attesterId), reputationRecords[attesterId].hash())
        }

        userStateRoot = userStateTree.getRootHash()
        // Global state tree
        GSTree = new IncrementalQuinTree(circuitGlobalStateTreeDepth, GSTZERO_VALUE, 2)
        const commitment = genIdentityCommitment(user)
        hashedLeaf = hashLeftRight(commitment, userStateRoot)
        GSTree.insert(hashedLeaf)
        GSTreeProof = GSTree.genMerklePath(0)
        GSTreeRoot = GSTree.root

        // selectors and reputation nonce
        for (let i = 0; i < repNullifiersAmount; i++) {
            nonceList.push( BigInt(nonceStarter + i) )
            selectors.push(BigInt(1));
        }
        for (let i = repNullifiersAmount ; i < maxReputationBudget; i++) {
            nonceList.push(BigInt(0))
            selectors.push(BigInt(0))
        }
    })

    it('successfully prove a random generated reputation', async () => {
        const attesterIds = Object.keys(reputationRecords)
        attesterId = attesterIds[Math.floor(Math.random() * NUM_ATTESTERS)]
        const USTPathElements = await userStateTree.getMerkleProof(BigInt(attesterId))

        const circuitInputs = {
            epoch: epoch,
            epoch_key_nonce: nonce,
            epoch_key: epochKey,
            identity_pk: user['keypair']['pubKey'],
            identity_nullifier: user['identityNullifier'], 
            identity_trapdoor: user['identityTrapdoor'],
            user_tree_root: userStateRoot,
            GST_path_index: GSTreeProof.indices,
            GST_path_elements: GSTreeProof.pathElements,
            GST_root: GSTreeRoot,
            attester_id: attesterId,
            pos_rep: reputationRecords[attesterId]['posRep'],
            neg_rep: reputationRecords[attesterId]['negRep'],
            graffiti: reputationRecords[attesterId]['graffiti'],
            sign_up: reputationRecords[attesterId]['signUp'],
            UST_path_elements: USTPathElements,
            rep_nullifiers_amount: repNullifiersAmount,
            selectors: selectors,
            rep_nonce: nonceList,
            min_rep: minRep,
            prove_graffiti: proveGraffiti,
            graffiti_pre_image: reputationRecords[attesterId]['graffitiPreImage']
        }
        const startTime = new Date().getTime()
        results = await genProofAndPublicSignals('proveReputation',stringifyBigInts(circuitInputs))
        const endTime = new Date().getTime()
        console.log(`Gen Proof time: ${endTime - startTime} ms (${Math.floor((endTime - startTime) / 1000)} s)`)
        const isValid = await verifyProof('proveReputation',results['proof'], results['publicSignals'])
        expect(isValid).to.be.true

        const isProofValid = await unirepContract.verifyReputation(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain failed').to.be.true
    })

    it('mismatched reputation nullifiers and nullifiers amount should fail', async () => {
        const wrongReputaionNullifierAmount = repNullifiersAmount + 1

        const isProofValid = await unirepContract.verifyReputation(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            wrongReputaionNullifierAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain should fail').to.be.false
    })

    it('wrong nullifiers should fail', async () => {
        const wrongReputaionNullifiers: BigInt[] = []
        for (let i = 0; i < maxReputationBudget; i++) {
            wrongReputaionNullifiers.push(genRandomSalt())
        }

        const isProofValid = await unirepContract.verifyReputation(
            wrongReputaionNullifiers,
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain should fail').to.be.false
    })

    it('wrong epoch should fail', async () => {
        const wrongEpoch = epoch + 1
        const isProofValid = await unirepContract.verifyReputation(
            results['publicSignals'].slice(0, maxReputationBudget),
            wrongEpoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain should fail').to.be.false
    })

    it('wrong epoch epoch should fail', async () => {
        const wrongEpochKey = genEpochKey(user['identityNullifier'], epoch, nonce + 1, circuitEpochTreeDepth)
        const isProofValid = await unirepContract.verifyReputation(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            wrongEpochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain should fail').to.be.false
    })

    it('wrong attesterId should fail', async () => {
        const wrongAttesterId = attesterId + 1
        const isProofValid = await unirepContract.verifyReputation(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            epochKey,
            GSTreeRoot,
            wrongAttesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain should fail').to.be.false
    })

    it('wrong minRep should fail', async () => {
        const wrongMinRep = minRep + 1
        const isProofValid = await unirepContract.verifyReputation(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            wrongMinRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain should fail').to.be.false
    })

    it('wrong graffiti preimage should fail', async () => {
        const wrongGraffitiPreimage = genRandomSalt()
        const isProofValid = await unirepContract.verifyReputation(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            wrongGraffitiPreimage,
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain should fail').to.be.false
    })

    it('sign up should succeed', async () => {
        const attester = accounts[1]
        const attesterAddress = await attester.getAddress()
        const unirepContractCalledByAttester = await hardhatEthers.getContractAt(Unirep.abi, unirepContract.address, attester)
        const tx = await unirepContractCalledByAttester.attesterSignUp()
        const receipt = await tx.wait()
        expect(receipt.status).equal(1)
        attesterId = await unirepContract.attesters(attesterAddress)
    })

    it('submit reputation nullifiers should succeed', async () => {
        const tx = await unirepContract.submitReputationNullifiers(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )
        const receipt = await tx.wait()
        expect(receipt.status).equal(1)
    })

    it('submit reputation nullifiers with invalid epoch should fail', async () => {
        const invalidEpoch = epoch + 1
        await expect(unirepContract.submitReputationNullifiers(
            results['publicSignals'].slice(0, maxReputationBudget),
            invalidEpoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )).to.be.revertedWith('Unirep: should submit a proof which matches current epoch')
    })

    it('submit reputation nullifiers with wrong length of nullifiers should fail', async () => {
        const wrongNullifiers = results['publicSignals'].slice(1, maxReputationBudget)
        await expect(unirepContract.submitReputationNullifiers(
            wrongNullifiers,
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )).to.be.revertedWith('Unirep: invalid number of rep nullifiers')
    })

    it('submit reputation nullifiers with invalid reputation amount should fail', async () => {
        const invalidRepAmount = maxReputationBudget + 1
        await expect(unirepContract.submitReputationNullifiers(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            invalidRepAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )).to.be.revertedWith('Unirep: invalid number of proving reputation amount')
    })

    it('submit reputation nullifiers with wrong attesterId should fail', async () => {
        const wrongAttesterId = attesterId + 1
        await expect(unirepContract.submitReputationNullifiers(
            results['publicSignals'].slice(0, maxReputationBudget),
            epoch,
            epochKey,
            GSTreeRoot,
            wrongAttesterId,
            repNullifiersAmount,
            minRep,
            proveGraffiti,
            reputationRecords[attesterId]['graffitiPreImage'],
            formatProofForVerifierContract(results['proof']),
        )).to.be.revertedWith('Unirep: invalid attesterId')
    })
})