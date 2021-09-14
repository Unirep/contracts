import { ethers as hardhatEthers } from 'hardhat'
import { ethers } from 'ethers'
import { expect } from "chai"
import { genProofAndPublicSignals, verifyProof, formatProofForVerifierContract } from "@unirep/circuits"
import { genRandomSalt, hashLeftRight, genIdentity, genIdentityCommitment, IncrementalQuinTree,  stringifyBigInts, SparseMerkleTreeImpl, hashOne, } from "@unirep/crypto"
import { circuitEpochTreeDepth, circuitGlobalStateTreeDepth, maxReputationBudget, circuitUserStateTreeDepth } from "../config"
import { genEpochKey, genNewUserStateTree, getTreeDepthsForTesting, Reputation } from './utils'
import { deployUnirep } from '../src'


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
            let attesterId = Math.ceil(Math.random() * (2 ** circuitUserStateTreeDepth - 1))
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

        // selectors and karma nonce
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
        const attesterId = attesterIds[Math.floor(Math.random() * NUM_ATTESTERS)]
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
        const results = await genProofAndPublicSignals('proveReputation',stringifyBigInts(circuitInputs))
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
})