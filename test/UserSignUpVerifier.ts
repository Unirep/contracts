import { ethers as hardhatEthers } from 'hardhat'
import { ethers } from 'ethers'
import { expect } from "chai"
import { genProofAndPublicSignals, verifyProof, formatProofForVerifierContract } from "@unirep/circuits"
import { genRandomSalt, hashLeftRight, genIdentity, genIdentityCommitment, IncrementalQuinTree,  stringifyBigInts, SparseMerkleTreeImpl, hashOne, } from "@unirep/crypto"
import { circuitEpochTreeDepth, circuitGlobalStateTreeDepth, } from "../config"
import { genEpochKey, genNewUserStateTree, getTreeDepthsForTesting, Reputation } from './utils'
import { deployUnirep } from '../src'


describe('Verify user sign up verifier', function () {
    this.timeout(30000)
    let unirepContract
    let accounts: ethers.Signer[]
    const epoch = 1
    const nonce = 0
    const user = genIdentity()
    const epochKey = genEpochKey(user['identityNullifier'], epoch, nonce, circuitEpochTreeDepth)

    let GSTZERO_VALUE = 0, GSTree, GSTreeRoot, GSTreeProof
    let userStateTree: SparseMerkleTreeImpl, userStateRoot
    let hashedLeaf
    let results

    let reputationRecords = {}
    const MIN_POS_REP = 20
    const MAX_NEG_REP = 10
    const signUp = 1
    const notSignUp = 0
    const signedUpAttesterId = 1
    const nonSignedUpAttesterId = 2

    before(async () => {
        accounts = await hardhatEthers.getSigners()

        const _treeDepths = getTreeDepthsForTesting()
        unirepContract = await deployUnirep(<ethers.Wallet>accounts[0], _treeDepths)
        // User state
        userStateTree = await genNewUserStateTree()

        // Bootstrap user state
        const graffitiPreImage = genRandomSalt()
        reputationRecords[signedUpAttesterId] = new Reputation(
            BigInt(Math.floor(Math.random() * 100) + MIN_POS_REP),
            BigInt(Math.floor(Math.random() * MAX_NEG_REP)),
            hashOne(graffitiPreImage),
            BigInt(signUp)
        )
        reputationRecords[signedUpAttesterId].addGraffitiPreImage(graffitiPreImage)
        await userStateTree.update(BigInt(signedUpAttesterId), reputationRecords[signedUpAttesterId].hash())

        reputationRecords[nonSignedUpAttesterId] = new Reputation(
            BigInt(Math.floor(Math.random() * 100) + MIN_POS_REP),
            BigInt(Math.floor(Math.random() * MAX_NEG_REP)),
            hashOne(graffitiPreImage),
            BigInt(notSignUp)
        )
        reputationRecords[nonSignedUpAttesterId].addGraffitiPreImage(graffitiPreImage)
        await userStateTree.update(BigInt(nonSignedUpAttesterId), reputationRecords[nonSignedUpAttesterId].hash())

        userStateRoot = userStateTree.getRootHash()
        // Global state tree
        GSTree = new IncrementalQuinTree(circuitGlobalStateTreeDepth, GSTZERO_VALUE, 2)
        const commitment = genIdentityCommitment(user)
        hashedLeaf = hashLeftRight(commitment, userStateRoot)
        GSTree.insert(hashedLeaf)
        GSTreeProof = GSTree.genMerklePath(0)
        GSTreeRoot = GSTree.root
    })

    it('successfully prove a user has signed up', async () => {
        const attesterId = signedUpAttesterId
        const USTPathElements = await userStateTree.getMerkleProof(BigInt(attesterId))

        const circuitInputs = {
            epoch: epoch,
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
        }
        const startTime = new Date().getTime()
        results = await genProofAndPublicSignals('proveUserSignUp',stringifyBigInts(circuitInputs))
        const endTime = new Date().getTime()
        console.log(`Gen Proof time: ${endTime - startTime} ms (${Math.floor((endTime - startTime) / 1000)} s)`)
        const isValid = await verifyProof('proveUserSignUp',results['proof'], results['publicSignals'])
        expect(isValid).to.be.true

        const isProofValid = await unirepContract.verifyUserSignUp(
            epoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify reputation proof on-chain failed').to.be.true
    })

    it('wrong attesterId should fail', async () => {
        const wrongAttesterId = nonSignedUpAttesterId
        const isProofValid = await unirepContract.verifyUserSignUp(
            epoch,
            epochKey,
            GSTreeRoot,
            wrongAttesterId,
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify user sign up proof on-chain should fail').to.be.false
    })

    it('wrong epoch should fail', async () => {
        const attesterId = signedUpAttesterId
        const wrongEpoch = epoch + 1
        const isProofValid = await unirepContract.verifyUserSignUp(
            wrongEpoch,
            epochKey,
            GSTreeRoot,
            attesterId,
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify user sign up proof on-chain should fail').to.be.false
    })

    it('wrong epoch key should fail', async () => {
        const attesterId = signedUpAttesterId
        const wrongEpochKey = genEpochKey(user['identityNullifier'], epoch, nonce + 1, circuitEpochTreeDepth)
        const isProofValid = await unirepContract.verifyUserSignUp(
            epoch,
            wrongEpochKey,
            GSTreeRoot,
            attesterId,
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify user sign up proof on-chain should fail').to.be.false
    })
})