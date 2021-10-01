import { ethers as hardhatEthers } from 'hardhat'
import { ethers } from 'ethers'
import { expect } from "chai"
import { genRandomSalt, hashLeftRight, IncrementalQuinTree, genIdentity, genIdentityCommitment, stringifyBigInts } from '@unirep/crypto'
import { formatProofForVerifierContract, genProofAndPublicSignals, verifyProof } from '@unirep/circuits'

import { attestingFee, epochLength, maxReputationBudget, numEpochKeyNoncePerEpoch } from '../config'
import { computeEmptyUserStateRoot, genEpochKey, getTreeDepthsForTesting, Attestation, IEpochTreeLeaf, UnirepState, UserState } from './utils'
import { deployUnirep } from '../src'
import Unirep from "../artifacts/contracts/Unirep.sol/Unirep.json"

describe('Epoch Transition', function () {
    this.timeout(1000000)

    let unirepContract: ethers.Contract
    let accounts: ethers.Signer[]

    let userId, userCommitment

    let attester, attesterAddress, attesterId, unirepContractCalledByAttester

    let numEpochKey

    let unirepState
    let userState
    let GSTree
    let circuitInputs
    let results
    const signedUpInLeaf = 1

    before(async () => {
        accounts = await hardhatEthers.getSigners()

        const _treeDepths = getTreeDepthsForTesting()
        unirepContract = await deployUnirep(<ethers.Wallet>accounts[0], _treeDepths)
        unirepState = new UnirepState(
            _treeDepths.globalStateTreeDepth,
            _treeDepths.userStateTreeDepth,
            _treeDepths.epochTreeDepth,
            attestingFee,
            epochLength,
            numEpochKeyNoncePerEpoch,
            maxReputationBudget,
        )

        console.log('User sign up')
        userId = genIdentity()
        userCommitment = genIdentityCommitment(userId)
        let tx = await unirepContract.userSignUp(userCommitment)
        let receipt = await tx.wait()
        expect(receipt.status).equal(1)
        
        const currentEpoch = await unirepContract.currentEpoch()
        const emptyUserStateRoot = computeEmptyUserStateRoot(_treeDepths.userStateTreeDepth)
        const hashedStateLeaf = await unirepContract.hashStateLeaf([userCommitment, emptyUserStateRoot])

        unirepState.signUp(currentEpoch.toNumber(), BigInt(hashedStateLeaf))
        userState = new UserState(
            unirepState,
            userId,
            userCommitment,
            false,
        )
        const latestTransitionedToEpoch = currentEpoch.toNumber()
        const GSTreeLeafIndex = 0
        userState.signUp(latestTransitionedToEpoch, GSTreeLeafIndex, 0, 0)

        console.log('Attester sign up')
        attester = accounts[1]
        attesterAddress = await attester.getAddress()
        unirepContractCalledByAttester = await hardhatEthers.getContractAt(Unirep.abi, unirepContract.address, attester)
        tx = await unirepContractCalledByAttester.attesterSignUp()
        receipt = await tx.wait()
        expect(receipt.status).equal(1)

        attesterId = await unirepContract.attesters(attesterAddress)

        // Submit 2 attestations
        let epoch = await unirepContract.currentEpoch()
        let nonce = 0
        let epochKey = genEpochKey(userId.identityNullifier, epoch, nonce)
        let circuitInputs = await userState.genVerifyEpochKeyCircuitInputs(nonce)
        results = await genProofAndPublicSignals('verifyEpochKey', stringifyBigInts(circuitInputs))
        let isValid = await verifyProof('verifyEpochKey', results['proof'], results['publicSignals'])
        let GSTRoot = results['publicSignals'][0]
        let epochKeyProof = [GSTRoot, formatProofForVerifierContract(results['proof'])]

        expect(isValid, 'Verify start transition circuit off-chain failed').to.be.true
        const attestationNum = 11
        for (let i = 0; i < attestationNum; i++) {
            let attestation = new Attestation(
                BigInt(attesterId.toString()),
                BigInt(i),
                BigInt(0),
                genRandomSalt(),
                BigInt(signedUpInLeaf),
            ) 
            tx = await unirepContractCalledByAttester.submitAttestation(
                attestation,
                epochKey,
                epochKeyProof,
                {value: attestingFee}
            )
            receipt = await tx.wait()
            expect(receipt.status).equal(1)
            unirepState.addAttestation(epochKey, attestation)
        }
        
        nonce = 1
        epochKey = genEpochKey(userId.identityNullifier, epoch, nonce)
        circuitInputs = await userState.genVerifyEpochKeyCircuitInputs(nonce)
        results = await genProofAndPublicSignals('verifyEpochKey', stringifyBigInts(circuitInputs))
        isValid = await verifyProof('verifyEpochKey', results['proof'], results['publicSignals'])
        GSTRoot = results['publicSignals'][0]
        epochKeyProof = [GSTRoot, formatProofForVerifierContract(results['proof'])]

        const attestation = new Attestation(
            BigInt(attesterId.toString()),
            BigInt(0),
            BigInt(99),
            BigInt(0),
            BigInt(signedUpInLeaf),
        )
        tx = await unirepContractCalledByAttester.submitAttestation(
            attestation,
            epochKey,
            epochKeyProof,
            {value: attestingFee}
        )
        receipt = await tx.wait()
        expect(receipt.status).equal(1)
        unirepState.addAttestation(epochKey, attestation)
    })

    it('premature epoch transition should fail', async () => {
        await expect(unirepContract.beginEpochTransition()
            ).to.be.revertedWith('Unirep: epoch not yet ended')
    })

    it('epoch transition should succeed', async () => {
        // Record data before epoch transition so as to compare them with data after epoch transition
        let epoch = await unirepContract.currentEpoch()

        // Fast-forward epochLength of seconds
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])
        // Assert no epoch transition compensation is dispensed to volunteer
        expect(await unirepContract.epochTransitionCompensation(attesterAddress)).to.be.equal(0)
        // Begin epoch transition 
        let tx = await unirepContractCalledByAttester.beginEpochTransition()
        let receipt = await tx.wait()
        expect(receipt.status).equal(1)
        console.log("Gas cost of sealing one epoch key:", receipt.gasUsed.toString())
        // Verify compensation to the volunteer increased
        expect(await unirepContract.epochTransitionCompensation(attesterAddress)).to.gt(0)

        // Complete epoch transition
        expect(await unirepContract.currentEpoch()).to.be.equal(epoch.add(1))

        // Verify latestEpochTransitionTime and currentEpoch
        let latestEpochTransitionTime = await unirepContract.latestEpochTransitionTime()
        expect(latestEpochTransitionTime).equal((await hardhatEthers.provider.getBlock(receipt.blockNumber)).timestamp)

        let epoch_ = await unirepContract.currentEpoch()
        expect(epoch_).equal(epoch.add(1))

        // Unirep and user state transition from the first epoch
        const epochTreeLeaves: IEpochTreeLeaf[] = []

        // Generate valid epoch tree leaves
        const attestationSubmittedFilter = unirepContract.filters.AttestationSubmitted()
        const attestationSubmittedEvents =  await unirepContract.queryFilter(attestationSubmittedFilter)
        const attestationMap = {}

        // compute hash chain of valid epoch key
        for (let i = 0; i < attestationSubmittedEvents.length; i++) {
            const isProofValid = await unirepContract.verifyEpochKeyValidity(
                attestationSubmittedEvents[i].args?.epkProofData?.fromGlobalStateTree,
                attestationSubmittedEvents[i].args?._epoch,
                attestationSubmittedEvents[i].args?._epochKey,
                attestationSubmittedEvents[i].args?.epkProofData?.proof,
            )
            if(isProofValid) {
                const epochKey = attestationSubmittedEvents[i].args?._epochKey
                if(attestationMap[epochKey] == undefined) {
                    attestationMap[epochKey] = BigInt(0)
                } 
                const attestation = new Attestation(
                    BigInt(attestationSubmittedEvents[i].args?.attestation?.attesterId.toString()),
                    BigInt(attestationSubmittedEvents[i].args?.attestation?.posRep.toString()),
                    BigInt(attestationSubmittedEvents[i].args?.attestation?.negRep.toString()),
                    BigInt(attestationSubmittedEvents[i].args?.attestation?.graffiti.toString()),
                    BigInt(attestationSubmittedEvents[i].args?.attestation?.signUp.toString()),
                )
                attestationMap[epochKey] = hashLeftRight(
                    attestation.hash(), 
                    attestationMap[epochKey]
                )
            }
        }

        // seal hash chain
        for(let k in attestationMap) {
            attestationMap[k] = hashLeftRight(BigInt(1), attestationMap[k])
            const epochTreeLeaf: IEpochTreeLeaf = {
                epochKey: BigInt(k),
                hashchainResult: attestationMap[k]
            }
            epochTreeLeaves.push(epochTreeLeaf)
        }

        unirepState.epochTransition(epoch, epochTreeLeaves)
    })
        
    it('start user state transition should succeed', async() => {
        circuitInputs = await userState.genUserStateTransitionCircuitInputs()
        results = await genProofAndPublicSignals('startTransition', circuitInputs.startTransitionProof)
        const isValid = await verifyProof('startTransition', results['proof'], results['publicSignals'])
        expect(isValid, 'Verify start transition circuit off-chain failed').to.be.true

        const blindedUserState = results['publicSignals'][0]
        const blindedHashChain = results['publicSignals'][1]
        const GSTreeRoot = results['publicSignals'][2]
        const tx = await unirepContract.startUserStateTransition(
            blindedUserState,
            blindedHashChain,
            GSTreeRoot,
            formatProofForVerifierContract(results['proof']),
        )
        const receipt = await tx.wait()
        expect(receipt.status, 'Submit user state transition proof failed').to.equal(1)
        console.log("Gas cost of submit a start transition proof:", receipt.gasUsed.toString())
    })

    it('submit process attestations proofs should succeed', async() => {
        for (let i = 0; i < circuitInputs.processAttestationProof.length; i++) {
            results = await genProofAndPublicSignals('processAttestations', circuitInputs.processAttestationProof[i])
            const isValid = await verifyProof('processAttestations', results['proof'], results['publicSignals'])
            expect(isValid, 'Verify process attestations circuit off-chain failed').to.be.true

            const outputBlindedUserState = results['publicSignals'][0]
            const outputBlindedHashChain = results['publicSignals'][1]
            const inputBlindedUserState = results['publicSignals'][2]

            const tx = await unirepContract.processAttestations(
                outputBlindedUserState,
                outputBlindedHashChain,
                inputBlindedUserState,
                formatProofForVerifierContract(results['proof']),
            )
            const receipt = await tx.wait()
            expect(receipt.status, 'Submit process attestations proof failed').to.equal(1)
            console.log("Gas cost of submit a process attestations proof:", receipt.gasUsed.toString())
        }
    })

    it('submit user state transition proofs should succeed', async() => {
        results = await genProofAndPublicSignals('userStateTransition', circuitInputs.finalTransitionProof)
        const isValid = await verifyProof('userStateTransition', results['proof'], results['publicSignals'])
        expect(isValid, 'Verify user state transition circuit off-chain failed').to.be.true

        const newGSTLeaf = results['publicSignals'][0]
        const outputEpkNullifiers = results['publicSignals'].slice(1,1 + numEpochKeyNoncePerEpoch)
        const blindedUserStates = results['publicSignals'].slice(2 + numEpochKeyNoncePerEpoch, 4 + numEpochKeyNoncePerEpoch)
        const blindedHashChains = results['publicSignals'].slice(5 + numEpochKeyNoncePerEpoch,5 + 2*numEpochKeyNoncePerEpoch)
        const fromEpoch = userState.latestTransitionedEpoch
        const fromEpochGSTree: IncrementalQuinTree = unirepState.genGSTree(fromEpoch)
        const GSTreeRoot = fromEpochGSTree.root
        const fromEpochTree = await unirepState.genEpochTree(fromEpoch)
        const epochTreeRoot = fromEpochTree.getRootHash()

        // Verify userStateTransition proof on-chain
        const isProofValid = await unirepContract.verifyUserStateTransition(
            newGSTLeaf,
            outputEpkNullifiers,
            fromEpoch,
            blindedUserStates,
            GSTreeRoot,
            blindedHashChains,
            epochTreeRoot,
            formatProofForVerifierContract(results['proof']),
        )
        expect(isProofValid, 'Verify user state transition circuit on-chain failed').to.be.true

        const tx = await unirepContract.updateUserStateRoot(
            newGSTLeaf,
            outputEpkNullifiers,
            blindedUserStates,
            blindedHashChains,
            fromEpoch,
            GSTreeRoot,
            epochTreeRoot,
            formatProofForVerifierContract(results['proof']),
        )
        const receipt = await tx.wait()
        expect(receipt.status, 'Submit user state transition proof failed').to.equal(1)
        console.log("Gas cost of submit a user state transition proof:", receipt.gasUsed.toString())

        const newState = await userState.genNewUserStateAfterTransition()
        const epkNullifiers = userState.getEpochKeyNullifiers(1)
        const epoch_ = await unirepContract.currentEpoch()
        expect(newGSTLeaf, 'Computed new GST leaf should match').to.equal(newState.newGSTLeaf.toString())
        userState.transition(newState.newUSTLeaves)
        unirepState.userStateTransition(epoch_, BigInt(newGSTLeaf), epkNullifiers)
    })

    it('epoch transition with no attestations and epoch keys should also succeed', async () => {
        let epoch = await unirepContract.currentEpoch()

        // Fast-forward epochLength of seconds
        await hardhatEthers.provider.send("evm_increaseTime", [epochLength])
        // Begin epoch transition
        let tx = await unirepContract.beginEpochTransition()
        let receipt = await tx.wait()
        expect(receipt.status).equal(1)

        // Verify latestEpochTransitionTime and currentEpoch
        let latestEpochTransitionTime = await unirepContract.latestEpochTransitionTime()
        expect(latestEpochTransitionTime).equal((await hardhatEthers.provider.getBlock(receipt.blockNumber)).timestamp)

        let epoch_ = await unirepContract.currentEpoch()
        expect(epoch_).equal(epoch.add(1))
    })

    it('collecting epoch transition compensation should succeed', async () => {
        const compensation = await unirepContract.epochTransitionCompensation(attesterAddress)
        expect(compensation).to.gt(0)
        // Set gas price to 0 so attester will not be charged transaction fee
        await expect(() => unirepContractCalledByAttester.collectEpochTransitionCompensation())
            .to.changeEtherBalance(attester, compensation)
        expect(await unirepContract.epochTransitionCompensation(attesterAddress)).to.equal(0)
    })
})