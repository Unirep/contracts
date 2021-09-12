import { ethers as hardhatEthers } from 'hardhat'
import { ethers } from 'ethers'
import { expect } from "chai"
import { genProofAndPublicSignals, verifyProof, formatProofForVerifierContract } from "@unirep/circuits"
import { genRandomSalt, hashLeftRight, genIdentity, genIdentityCommitment, IncrementalQuinTree,  stringifyBigInts, } from "@unirep/crypto"
import { numEpochKeyNoncePerEpoch, circuitEpochTreeDepth, circuitGlobalStateTreeDepth } from "../config"
import { genEpochKey, getTreeDepthsForTesting } from './utils'
import { deployUnirep } from '../src'


describe('Verify Epoch Key verifier', function () {
    this.timeout(30000)

    let ZERO_VALUE = 0

    const maxEPK = BigInt(2 ** circuitEpochTreeDepth)

    let unirepContract
    let accounts: ethers.Signer[]
    let id, commitment, stateRoot
    let tree, proof, root
    let nonce, currentEpoch, epochKey
    let results

    before(async () => {
        accounts = await hardhatEthers.getSigners()

        const _treeDepths = getTreeDepthsForTesting()
        unirepContract = await deployUnirep(<ethers.Wallet>accounts[0], _treeDepths)
        tree = new IncrementalQuinTree(circuitGlobalStateTreeDepth, ZERO_VALUE, 2)
        id = genIdentity()
        commitment = genIdentityCommitment(id)
        stateRoot = genRandomSalt()

        const hashedStateLeaf = hashLeftRight(commitment.toString(), stateRoot.toString())
        tree.insert(BigInt(hashedStateLeaf.toString()))
        proof = tree.genMerklePath(0)
        root = tree.root

        nonce = 0
        currentEpoch = 1
        epochKey = genEpochKey(id['identityNullifier'], currentEpoch, nonce, circuitEpochTreeDepth)
    })

    it('Valid epoch key should pass check', async () => {
        // Check if every valid nonce works
        for (let i = 0; i < numEpochKeyNoncePerEpoch; i++) {
            const n = i
            const epk = genEpochKey(id['identityNullifier'], currentEpoch, n, circuitEpochTreeDepth)
            
            const circuitInputs = {
                GST_path_elements: proof.pathElements,
                GST_path_index: proof.indices,
                GST_root: root,
                identity_pk: id['keypair']['pubKey'],
                identity_nullifier: id['identityNullifier'], 
                identity_trapdoor: id['identityTrapdoor'],
                user_tree_root: stateRoot,
                nonce: n,
                epoch: currentEpoch,
                epoch_key: epk,
            }
            const startTime = new Date().getTime()
            results = await genProofAndPublicSignals('verifyEpochKey', stringifyBigInts(circuitInputs))
            const endTime = new Date().getTime()
            console.log(`Gen Proof time: ${endTime - startTime} ms (${Math.floor((endTime - startTime) / 1000)} s)`)
            const isValid = await verifyProof('verifyEpochKey', results['proof'], results['publicSignals'])
            expect(isValid).to.be.true

            const isProofValid = await unirepContract.verifyEpochKeyValidity(
                root,
                currentEpoch,
                epk,
                formatProofForVerifierContract(results['proof']),
            )
            expect(isProofValid, 'Verify epk proof on-chain failed').to.be.true
            epochKey = epk
        }
    })

    it('Invalid epoch key should not pass check', async () => {
        // Validate against invalid epoch key
        const invalidEpochKey1 = maxEPK
        const isProofValid = await unirepContract.verifyEpochKeyValidity(
            root,
            currentEpoch,
            invalidEpochKey1,
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify epk proof on-chain should fail').to.be.false
    })

    it('Mismatched GST tree root should not pass check', async () => {
        const otherTreeRoot = genRandomSalt()
        const isProofValid = await unirepContract.verifyEpochKeyValidity(
            otherTreeRoot,
            currentEpoch,
            epochKey,
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify epk proof on-chain should fail').to.be.false
    })

    it('Invalid epoch should not pass check', async () => {
        let invalidEpoch, invalidEpochKey
        invalidEpoch = currentEpoch + 1
        invalidEpochKey = genEpochKey(id['identityNullifier'], invalidEpoch, nonce, circuitEpochTreeDepth)
        while (invalidEpochKey == epochKey) {
            invalidEpoch += 1
            invalidEpochKey = genEpochKey(id['identityNullifier'], invalidEpoch, nonce, circuitEpochTreeDepth)
        }
        
        expect(await unirepContract.verifyEpochKeyValidity(
            root,
            invalidEpoch,
            epochKey,
            formatProofForVerifierContract(results['proof']),
        ), 'Verify epk proof on-chain should fail').to.be.false
    })
})