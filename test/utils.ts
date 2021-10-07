// The reason for the ts-ignore below is that if we are executing the code via `ts-node` instead of `hardhat`,
// it can not read the hardhat config and error ts-2503 will be reported.
// @ts-ignore
import assert from 'assert'
import { ethers } from 'ethers'
import Keyv from "keyv"
import { hash5, hashLeftRight, SparseMerkleTreeImpl, add0x, SnarkBigInt, hashOne, stringifyBigInts } from '@unirep/crypto'
import { IncrementalQuinTree } from 'maci-crypto'
import { circuitEpochTreeDepth, circuitUserStateTreeDepth, circuitGlobalStateTreeDepth, numAttestationsPerProof, maxReputationBudget } from '../config'

const SMT_ZERO_LEAF = hashLeftRight(BigInt(0), BigInt(0))
const SMT_ONE_LEAF = hashLeftRight(BigInt(1), BigInt(0))
const EPOCH_KEY_NULLIFIER_DOMAIN = BigInt(1)

interface IEpochTreeLeaf {
    epochKey: BigInt;
    hashchainResult: BigInt;
}

interface IUserStateLeaf {
    attesterId: BigInt;
    reputation: Reputation;
}

interface IAttestation {
    attesterId: BigInt;
    posRep: BigInt;
    negRep: BigInt;
    graffiti: BigInt;
    signUp: BigInt;
    hash(): BigInt;
}

class Attestation implements IAttestation {
    public attesterId: BigInt
    public posRep: BigInt
    public negRep: BigInt
    public graffiti: BigInt
    public signUp: BigInt

    constructor(
        _attesterId: BigInt,
        _posRep: BigInt,
        _negRep: BigInt,
        _graffiti: BigInt,
        _signUp: BigInt,
    ) {
        this.attesterId = _attesterId
        this.posRep = _posRep
        this.negRep = _negRep
        this.graffiti = _graffiti
        this.signUp = _signUp
    }

    public hash = (): BigInt => {
        return hash5([
            this.attesterId,
            this.posRep,
            this.negRep,
            this.graffiti,
            this.signUp,
        ])
    }
}

interface IReputation {
    posRep: BigInt;
    negRep: BigInt;
    graffiti: BigInt;
    signUp: BigInt;
}

class Reputation implements IReputation {
    public posRep: BigInt
    public negRep: BigInt
    public graffiti: BigInt
    public graffitiPreImage: BigInt = BigInt(0)
    public signUp: BigInt

    constructor(
        _posRep: BigInt,
        _negRep: BigInt,
        _graffiti: BigInt,
        _signUp: BigInt,
    ) {
        this.posRep = _posRep
        this.negRep = _negRep
        this.graffiti = _graffiti
        this.signUp = _signUp
    }

    public static default(): Reputation {
        return new Reputation(BigInt(0), BigInt(0), BigInt(0), BigInt(0))
    }

    public update = (
        _posRep: BigInt,
        _negRep: BigInt,
        _graffiti: BigInt,
        _signUp: BigInt,
    ): Reputation => {
        this.posRep = BigInt(Number(this.posRep) + Number(_posRep))
        this.negRep = BigInt(Number(this.negRep) + Number(_negRep))
        if(_graffiti != BigInt(0)){
            this.graffiti = _graffiti
        }
        this.signUp = this.signUp || _signUp
        return this
    }

    public addGraffitiPreImage = (_graffitiPreImage: BigInt) => {
        assert(hashOne(_graffitiPreImage) === this.graffiti, 'Graffiti pre-image does not match')
        this.graffitiPreImage = _graffitiPreImage
    }

    public hash = (): BigInt => {
        return hash5([
            this.posRep,
            this.negRep,
            this.graffiti,
            this.signUp,
            BigInt(0),
        ])
    }
}

class UnirepState {
    public globalStateTreeDepth: number
    public userStateTreeDepth: number
    public epochTreeDepth: number

    public attestingFee: ethers.BigNumber
    public epochLength: number
    public numEpochKeyNoncePerEpoch: number
    public maxReputationBudget: number
    
    public currentEpoch: number
    public defaultGSTLeaf: BigInt
    private GSTLeaves: {[key: number]: BigInt[]} = {}
    private epochTreeLeaves: {[key: number]: IEpochTreeLeaf[]} = {}
    private nullifiers: BigInt[] = []

    private epochKeyToHashchainMap: {[key: string]: BigInt} = {}
    private epochKeyToAttestationsMap: {[key: string]: IAttestation[]} = {}

    constructor(
        _globalStateTreeDepth: number,
        _userStateTreeDepth: number,
        _epochTreeDepth: number,
        _attestingFee: ethers.BigNumber,
        _epochLength: number,
        _numEpochKeyNoncePerEpoch: number,
        _maxReputationBudget: number
    ) {

        this.globalStateTreeDepth = _globalStateTreeDepth
        this.userStateTreeDepth = _userStateTreeDepth
        this.epochTreeDepth = _epochTreeDepth
        this.attestingFee = _attestingFee
        this.epochLength = _epochLength
        this.numEpochKeyNoncePerEpoch = _numEpochKeyNoncePerEpoch
        this.maxReputationBudget = _maxReputationBudget

        this.currentEpoch = 1
        this.GSTLeaves[this.currentEpoch] = []
        const emptyUserStateRoot = computeEmptyUserStateRoot(_userStateTreeDepth)
        this.defaultGSTLeaf = hashLeftRight(BigInt(0), emptyUserStateRoot)
    }

    /*
     * Get the number of GST leaves of given epoch
     */
    public getNumGSTLeaves = (epoch: number): number => {
        if (epoch > this.currentEpoch) return 0
        return this.GSTLeaves[epoch].length
    }

    /*
     * Get the hash chain result of given epoch key
     */
    public getHashchain = (epochKey: string): BigInt => {
        const DefaultHashchainResult = SMT_ONE_LEAF
        const hashchain = this.epochKeyToHashchainMap[epochKey]
        if (!hashchain) return DefaultHashchainResult
        else return hashchain
    }

    /*
     * Get the attestations of given epoch key
     */
    public getAttestations = (epochKey: string): IAttestation[] => {
        const attestations = this.epochKeyToAttestationsMap[epochKey]
        if (!attestations) return []
        else return attestations
    }

    /*
     * Check if given nullifier exists in nullifier tree
     */
    public nullifierExist = (nullifier: BigInt): boolean => {
        if (nullifier === BigInt(0)) {
            console.log("Nullifier 0 exists because it is reserved")
            return true
        }
        return (this.nullifiers.indexOf(nullifier) !== -1)
    }


    /*
     * Add a new attestation to the list of attestations to the epoch key.
     */
    public addAttestation = (
        epochKey: string,
        attestation: IAttestation,
    ) => {
        const attestations = this.epochKeyToAttestationsMap[epochKey]
        if (!attestations) this.epochKeyToAttestationsMap[epochKey] = []
        this.epochKeyToAttestationsMap[epochKey].push(attestation)
    }

    /*
     * Computes the global state tree of given epoch
     */
    public genGSTree = (epoch: number): IncrementalQuinTree => {
        const GSTree = new IncrementalQuinTree(
            this.globalStateTreeDepth,
            this.defaultGSTLeaf,
            2,
        )

        const leaves = this.GSTLeaves[epoch]
        for (const leaf of leaves) {
            GSTree.insert(leaf)
        }
        return GSTree
    }

    /*
     * Computes the epoch tree of given epoch
     */
    public genEpochTree = async (epoch: number): Promise<SparseMerkleTreeImpl> => {
        const epochTree = await genNewSMT(this.epochTreeDepth, SMT_ONE_LEAF)

        const leaves = this.epochTreeLeaves[epoch]
        if (!leaves) return epochTree
        else {
            for (const leaf of leaves) {
                await epochTree.update(leaf.epochKey, leaf.hashchainResult)
            }
            return epochTree
        }
    }

    /*
     * Add a new state leaf to the list of GST leaves of given epoch.
     */
    public signUp = (
        epoch: number,
        GSTLeaf: BigInt,
    ) => {
        assert(epoch == this.currentEpoch, `Epoch(${epoch}) must be the same as current epoch`)

        // Note that we do not insert a state leaf to any state tree here. This
        // is because we want to keep the state minimal, and only compute what
        // is necessary when it is needed. This may change if we run into
        // severe performance issues, but it is currently worth the tradeoff.
        this.GSTLeaves[epoch].push(GSTLeaf)
    }

    /*
     * Add the leaves of epoch tree of given epoch and increment current epoch number
     */
    public epochTransition = (
        epoch: number,
        epochTreeLeaves: IEpochTreeLeaf[],
    ) => {
        assert(epoch == this.currentEpoch, `Epoch(${epoch}) must be the same as current epoch`)

        // Add to epoch key hash chain map
        for (let leaf of epochTreeLeaves) {
            assert(leaf.epochKey < BigInt(2 ** this.epochTreeDepth), `Epoch key(${leaf.epochKey}) greater than max leaf value(2**epochTreeDepth)`)
            if (this.epochKeyToHashchainMap[leaf.epochKey.toString()] !== undefined) console.log(`The epoch key(${leaf.epochKey}) is seen before`)
            else this.epochKeyToHashchainMap[leaf.epochKey.toString()] = leaf.hashchainResult
        }
        this.epochTreeLeaves[epoch] = epochTreeLeaves.slice()
        this.currentEpoch ++
        this.GSTLeaves[this.currentEpoch] = []
    }

    /*
     * Add a new state leaf to the list of GST leaves of given epoch.
     */
    public userStateTransition = (
        epoch: number,
        GSTLeaf: BigInt,
        nullifiers: BigInt[],
    ) => {
        assert(epoch == this.currentEpoch, `Epoch(${epoch}) must be the same as current epoch`)

        // Only insert non-zero GST leaf (zero GST leaf means the user has epoch keys left to process)
        if (GSTLeaf > BigInt(0)) this.GSTLeaves[epoch].push(GSTLeaf)

        for (let nullifier of nullifiers) {
            if (nullifier > BigInt(0)) {
                assert(this.nullifiers.indexOf(nullifier) == -1, `Nullifier(${nullifier}) seen before`)
                this.nullifiers.push(nullifier)
            }
        }
    }
}

class UserState {
    public userStateTreeDepth: number
    public numEpochKeyNoncePerEpoch: number
    public numAttestationsPerProof: number

    private unirepState: UnirepState

    public id
    public commitment
    private hasSignedUp: boolean = false

    public latestTransitionedEpoch: number  // Latest epoch where the user has a record in the GST of that epoch
    public latestGSTLeafIndex: number  // Leaf index of the latest GST where the user has a record in
    private latestUserStateLeaves: IUserStateLeaf[]  // Latest non-default user state leaves

    constructor(
        _unirepState: UnirepState,
        _id,
        _commitment,
        _hasSignedUp: boolean,
        _transitionedPosRep?: number,
        _transitionedNegRep?: number,
        _currentEpochPosRep?: number,
        _currentEpochNegRep?: number,
        _latestTransitionedEpoch?: number,
        _latestGSTLeafIndex?: number,
        _latestUserStateLeaves?: IUserStateLeaf[],
    ) {
        assert(_unirepState !== undefined, "UnirepState is undefined")
        this.unirepState = _unirepState
        this.userStateTreeDepth = this.unirepState.userStateTreeDepth
        this.numEpochKeyNoncePerEpoch = this.unirepState.numEpochKeyNoncePerEpoch
        this.numAttestationsPerProof = numAttestationsPerProof

        this.id = _id
        this.commitment = _commitment
        if (_hasSignedUp) {
            assert(_latestTransitionedEpoch !== undefined, "User has signed up but missing latestTransitionedEpoch")
            assert(_latestGSTLeafIndex !== undefined, "User has signed up but missing latestTransitionedEpoch")
            assert(_transitionedPosRep !== undefined, "User has signed up but missing transitionedPosRep")
            assert(_transitionedNegRep !== undefined, "User has signed up but missing transitionedNegRep")
            assert(_currentEpochPosRep !== undefined, "User has signed up but missing currentEpochPosRep")
            assert(_currentEpochNegRep !== undefined, "User has signed up but missing currentEpochNegRep")

            this.latestTransitionedEpoch = _latestTransitionedEpoch
            this.latestGSTLeafIndex = _latestGSTLeafIndex
            if (_latestUserStateLeaves !== undefined) this.latestUserStateLeaves = _latestUserStateLeaves
            else this.latestUserStateLeaves = []
            this.hasSignedUp = _hasSignedUp
        } else {
            this.latestTransitionedEpoch = 0
            this.latestGSTLeafIndex = 0
            this.latestUserStateLeaves = []
        }
    }
    

    public getUnirepStateGSTree = (epoch: number): IncrementalQuinTree => {
        return this.unirepState.genGSTree(epoch)
    }

    public getUnirepStateEpochTree = async (epoch: number): Promise<SparseMerkleTreeImpl> => {
        return this.unirepState.genEpochTree(epoch)
    }

    /*
     * Get the attestations of given epoch key
     */
    public getAttestations = (epochKey: string): IAttestation[] => {
        return this.unirepState.getAttestations(epochKey)
    }

    /*
     * Get the epoch key nullifier of given epoch
     */
    public getEpochKeyNullifiers = (epoch: number): BigInt[] => {
        const nullifiers: BigInt[] = []
        for (let nonce = 0; nonce < this.numEpochKeyNoncePerEpoch; nonce++) {
            const nullifier = genEpochKeyNullifier(this.id.identityNullifier, epoch, nonce)
            nullifiers.push(nullifier)
        }
        return nullifiers
    }

    public getRepByAttester = (attesterId: BigInt): Reputation => {
        const leaf = this.latestUserStateLeaves.find((leaf) => leaf.attesterId == attesterId)
        if (leaf !== undefined) return leaf.reputation
        else return Reputation.default()
    }

    /*
     * Check if given nullifier exists in nullifier tree
     */
    public nullifierExist = (nullifier: BigInt): boolean => {
        return this.unirepState.nullifierExist(nullifier)
    }

    /*
     * Add a new epoch key to the list of epoch key of current epoch.
     */
    public signUp = (_latestTransitionedEpoch: number, _latestGSTLeafIndex: number, _attesterId: number, _airdropAmount: number) => {
        assert(!this.hasSignedUp, "User has already signed up")
        this.latestTransitionedEpoch = _latestTransitionedEpoch
        this.latestGSTLeafIndex = _latestGSTLeafIndex
        this.hasSignedUp = true
        const signUpInLeaf = 1
        if(_attesterId && _airdropAmount) {
            const stateLeave: IUserStateLeaf = {
                attesterId: BigInt(_attesterId),
                reputation: Reputation.default().update(BigInt(_airdropAmount), BigInt(0), BigInt(0), BigInt(signUpInLeaf))
            }
            this.latestUserStateLeaves = [ stateLeave ]
        }
    }

    /*
     * Computes the user state tree with given state leaves
     */
    private _genUserStateTreeFromLeaves = async (leaves: IUserStateLeaf[]): Promise<SparseMerkleTreeImpl> => {
        const USTree = await genNewSMT(this.userStateTreeDepth, defaultUserStateLeaf)

        for (const leaf of leaves) {
            await USTree.update(leaf.attesterId, leaf.reputation.hash())
        }
        return USTree
    }

    /*
     * Computes the user state tree of given epoch
     */
    public genUserStateTree = async (): Promise<SparseMerkleTreeImpl> => {
        const leaves = this.latestUserStateLeaves
        return (await this._genUserStateTreeFromLeaves(leaves))
    }


    public genVerifyEpochKeyCircuitInputs = async (
        epochKeyNonce: number,
    ) => {
        assert(this.hasSignedUp, "User has not signed up yet")
        assert(epochKeyNonce < this.numEpochKeyNoncePerEpoch, `epochKeyNonce(${epochKeyNonce}) must be less than max epoch nonce`)
        const epoch = this.latestTransitionedEpoch
        const epochKey = genEpochKey(this.id.identityNullifier, epoch, epochKeyNonce, this.unirepState.epochTreeDepth)

        const userStateTree = await this.genUserStateTree()

        const GSTree = this.unirepState.genGSTree(epoch)
        const GSTProof = GSTree.genMerklePath(this.latestGSTLeafIndex)

        return stringifyBigInts({
            GST_path_elements: GSTProof.pathElements,
            GST_path_index: GSTProof.indices,
            GST_root: GSTree.root,
            identity_pk: this.id.keypair.pubKey,
            identity_nullifier: this.id.identityNullifier, 
            identity_trapdoor: this.id.identityTrapdoor,
            user_tree_root: userStateTree.getRootHash(),
            nonce: epochKeyNonce,
            epoch: epoch,
            epoch_key: epochKey,
        })
    }

    private _updateUserStateLeaf = (attestation: IAttestation, stateLeaves: IUserStateLeaf[]): IUserStateLeaf[] => {
        const attesterId = attestation.attesterId
        for (const leaf of stateLeaves) {
            if (leaf.attesterId === attesterId) {
                leaf.reputation = leaf.reputation.update(
                    attestation.posRep,
                    attestation.negRep,
                    attestation.graffiti,
                    attestation.signUp,
                )
                return stateLeaves
            }
        }
        // If no matching state leaf, insert new one
        const newLeaf: IUserStateLeaf = {
            attesterId: attesterId,
            reputation: Reputation.default().update(attestation.posRep, attestation.negRep, attestation.graffiti, attestation.signUp)
        }
        stateLeaves.push(newLeaf)
        return stateLeaves
    }

    public genNewUserStateAfterTransition = async () => {
        assert(this.hasSignedUp, "User has not signed up yet")
        const fromEpoch = this.latestTransitionedEpoch

        let stateLeaves: IUserStateLeaf[]
        stateLeaves = this.latestUserStateLeaves.slice()

        for (let nonce = 0; nonce < this.numEpochKeyNoncePerEpoch; nonce++) {
            const epkNullifier = genEpochKeyNullifier(this.id.identityNullifier, fromEpoch, nonce)
            assert(! this.unirepState.nullifierExist(epkNullifier), `Epoch key with nonce ${nonce} is already processed, it's nullifier: ${epkNullifier}`)

            const epochKey = genEpochKey(this.id.identityNullifier, fromEpoch, nonce, this.unirepState.epochTreeDepth)
            const attestations = this.unirepState.getAttestations(epochKey.toString())
            for (let i = 0; i < attestations.length; i++) {
                const attestation = attestations[i]
                stateLeaves = this._updateUserStateLeaf(attestation, stateLeaves)
            }
        }

        // Gen new user state tree
        const newUserStateTree = await this._genUserStateTreeFromLeaves(stateLeaves)
    
        // Gen new GST leaf
        const newGSTLeaf = hashLeftRight(this.commitment, newUserStateTree.getRootHash())
        return {
            'newGSTLeaf': newGSTLeaf,
            'newUSTLeaves': stateLeaves
        }
    }

    private _genStartTransitionCircuitInputs = async (fromNonce: number, userStateTreeRoot: BigInt, GSTreeProof: any, GSTreeRoot: BigInt) => {
        // Circuit inputs
        const circuitInputs = stringifyBigInts({
            epoch: this.latestTransitionedEpoch,
            nonce: fromNonce,
            user_tree_root: userStateTreeRoot,
            identity_pk: this.id.keypair.pubKey,
            identity_nullifier: this.id.identityNullifier,
            identity_trapdoor: this.id.identityTrapdoor,
            GST_path_elements: GSTreeProof.pathElements,
            GST_path_index: GSTreeProof.indices,
            GST_root: GSTreeRoot,
        })

        // Circuit outputs
        // blinded user state and blinded hash chain are the inputs of processAttestationProofs
        const blindedUserState = hash5([
            this.id.identityNullifier,
            userStateTreeRoot,
            this.latestTransitionedEpoch,
            fromNonce,
            BigInt(0)
        ])
        const blindedHashChain = hash5([
            this.id.identityNullifier,
            BigInt(0), // hashchain starter
            this.latestTransitionedEpoch,
            fromNonce,
            BigInt(0)
        ])

        return {
            circuitInputs: circuitInputs,
            blindedUserState: blindedUserState,
            blindedHashChain: blindedHashChain,
        }
    }

    public genUserStateTransitionCircuitInputs = async () => {
        assert(this.hasSignedUp, "User has not signed up yet")
        const fromEpoch = this.latestTransitionedEpoch
        const fromNonce = 0

        // User state tree
        const fromEpochUserStateTree: SparseMerkleTreeImpl = await this.genUserStateTree()
        const intermediateUserStateTreeRoots: BigInt[] = [
            fromEpochUserStateTree.getRootHash()
        ]
        const userStateLeafPathElements: any[] = []
        // GSTree
        const fromEpochGSTree: IncrementalQuinTree = this.unirepState.genGSTree(fromEpoch)
        const GSTreeProof = fromEpochGSTree.genMerklePath(this.latestGSTLeafIndex)
        const GSTreeRoot = fromEpochGSTree.root
        // Epoch tree
        const fromEpochTree = await this.unirepState.genEpochTree(fromEpoch)
        const epochTreeRoot = fromEpochTree.getRootHash()
        const epochKeyPathElements: any[] = []

        // start transition proof
        const startTransitionProof = await this._genStartTransitionCircuitInputs(fromNonce, intermediateUserStateTreeRoots[0], GSTreeProof, GSTreeRoot)
        
        // process attestation proof
        const processAttestationProofs: any[] = []
        const fromNonces: number[] = [ fromNonce ]
        const toNonces: number[] = []
        const hashChainStarter: BigInt[] = []
        const blindedUserState: BigInt[] = [ startTransitionProof.blindedUserState ]
        const blindedHashChain: BigInt[] = []
        let reputationRecords = {}
        const selectors: number[] = []
        const attesterIds: BigInt[] = []
        const oldPosReps: BigInt[] = [], oldNegReps: BigInt[] = [], oldGraffities: BigInt[] = [], oldSignUps: BigInt[] = []
        const posReps: BigInt[] = [], negReps: BigInt[] = [], graffities: BigInt[] = [], overwriteGraffities: any[] = [], signUps: BigInt[] = []
        const finalBlindedUserState: BigInt[] = []
        const finalUserState: BigInt[] = [ intermediateUserStateTreeRoots[0] ]
        const finalHashChain: BigInt[] = []

        for (let nonce = 0; nonce < this.numEpochKeyNoncePerEpoch; nonce++) {
            const epochKey = genEpochKey(this.id.identityNullifier, fromEpoch, nonce, this.unirepState.epochTreeDepth)
            let currentHashChain: BigInt = BigInt(0)

            // Blinded user state and hash chain of the epoch key
            toNonces.push(nonce)
            hashChainStarter.push(currentHashChain)

            // Attestations
            const attestations = this.unirepState.getAttestations(epochKey.toString())
            for (let i = 0; i < attestations.length; i++) {

                // Include a blinded user state and blinded hash chain per proof
                if(i && (i % this.numAttestationsPerProof == 0) && (i != this.numAttestationsPerProof - 1)){
                    toNonces.push(nonce)
                    fromNonces.push(nonce)
                    hashChainStarter.push(currentHashChain)
                    blindedUserState.push(hash5([this.id.identityNullifier, fromEpochUserStateTree.getRootHash(), fromEpoch, nonce]))
                }

                const attestation = attestations[i]
                const attesterId = attestation.attesterId
                const rep = this.getRepByAttester(attesterId)

                if (reputationRecords[attesterId.toString()] === undefined) {
                    reputationRecords[attesterId.toString()] = new Reputation(
                        rep.posRep,
                        rep.negRep,
                        rep.graffiti,
                        rep.signUp,
                    )
                }

                oldPosReps.push(reputationRecords[attesterId.toString()]['posRep'])
                oldNegReps.push(reputationRecords[attesterId.toString()]['negRep'])
                oldGraffities.push(reputationRecords[attesterId.toString()]['graffiti'])
                oldSignUps.push(reputationRecords[attesterId.toString()]['signUp'])

                // Add UST merkle proof to the list
                const USTLeafPathElements = await fromEpochUserStateTree.getMerkleProof(attesterId)
                userStateLeafPathElements.push(USTLeafPathElements)

                // Update attestation record
                reputationRecords[attesterId.toString()].update(
                    attestation['posRep'],
                    attestation['negRep'],
                    attestation['graffiti'],
                    attestation['signUp'],
                )

                // Update UST
                await fromEpochUserStateTree.update(attesterId, reputationRecords[attesterId.toString()].hash())
                // Add new UST root to intermediate UST roots
                intermediateUserStateTreeRoots.push(fromEpochUserStateTree.getRootHash())
                
                selectors.push(1)
                attesterIds.push(attesterId)
                posReps.push(attestation['posRep'])
                negReps.push(attestation['negRep'])
                graffities.push(attestation['graffiti'])
                overwriteGraffities.push(attestation['graffiti'] != BigInt(0))
                signUps.push(attestation['signUp'])

                // Update current hashchain result
                const attestationHash = attestation.hash()
                currentHashChain = hashLeftRight(attestationHash, currentHashChain)
            }
            // Fill in blank data for non-exist attestation
            const filledAttestationNum = attestations.length ? Math.ceil(attestations.length / this.numAttestationsPerProof) * this.numAttestationsPerProof : this.numAttestationsPerProof
            for (let i = 0; i < (filledAttestationNum - attestations.length); i++) {
                oldPosReps.push(BigInt(0))
                oldNegReps.push(BigInt(0))
                oldGraffities.push(BigInt(0))
                oldSignUps.push(BigInt(0))
                
                const USTLeafZeroPathElements = await fromEpochUserStateTree.getMerkleProof(BigInt(0))
                userStateLeafPathElements.push(USTLeafZeroPathElements)
                intermediateUserStateTreeRoots.push(fromEpochUserStateTree.getRootHash())

                selectors.push(0)
                attesterIds.push(BigInt(0))
                posReps.push(BigInt(0))
                negReps.push(BigInt(0))
                graffities.push(BigInt(0))
                overwriteGraffities.push(BigInt(0))
                signUps.push(BigInt(0))
            }
            epochKeyPathElements.push(await fromEpochTree.getMerkleProof(epochKey))
            finalHashChain.push(currentHashChain)
            blindedUserState.push(hash5([this.id.identityNullifier, fromEpochUserStateTree.getRootHash(), fromEpoch, nonce]))
            blindedHashChain.push(hash5([this.id.identityNullifier, currentHashChain, fromEpoch, nonce]))
            if(nonce != this.numEpochKeyNoncePerEpoch - 1) fromNonces.push(nonce)
        }

        for (let i = 0; i < fromNonces.length; i++) {
            const startIdx = this.numAttestationsPerProof * i
            const endIdx = this.numAttestationsPerProof * (i+1)
            // if(fromNonces[i] == toNonces[i] && intermediateUserStateTreeRoots[startIdx] == intermediateUserStateTreeRoots[endIdx]) continue
            processAttestationProofs.push(stringifyBigInts({
                epoch: fromEpoch,
                from_nonce: fromNonces[i],
                to_nonce: toNonces[i],
                identity_nullifier: this.id.identityNullifier,
                intermediate_user_state_tree_roots: intermediateUserStateTreeRoots.slice(startIdx, endIdx + 1),
                old_pos_reps: oldPosReps.slice(startIdx, endIdx),
                old_neg_reps: oldNegReps.slice(startIdx, endIdx),
                old_graffities: oldGraffities.slice(startIdx, endIdx),
                old_sign_ups: oldSignUps.slice(startIdx, endIdx),
                path_elements: userStateLeafPathElements.slice(startIdx, endIdx),
                attester_ids: attesterIds.slice(startIdx, endIdx),
                pos_reps: posReps.slice(startIdx, endIdx),
                neg_reps: negReps.slice(startIdx, endIdx),
                graffities: graffities.slice(startIdx, endIdx),
                overwrite_graffities: overwriteGraffities.slice(startIdx, endIdx),
                sign_ups: signUps.slice(startIdx, endIdx),
                selectors: selectors.slice(startIdx, endIdx),
                hash_chain_starter: hashChainStarter[i],
                input_blinded_user_state: blindedUserState[i],
            }))
        }

        // final user state transition proof
        const startEpochKeyNonce = 0
        const endEpochKeyNonce = this.numEpochKeyNoncePerEpoch - 1
        finalUserState.push(fromEpochUserStateTree.getRootHash())
        finalBlindedUserState.push(hash5([this.id.identityNullifier, finalUserState[0], fromEpoch, startEpochKeyNonce]))
        finalBlindedUserState.push(hash5([this.id.identityNullifier, finalUserState[1], fromEpoch, endEpochKeyNonce]))
        const finalTransitionProof = stringifyBigInts({
            epoch: fromEpoch,
            blinded_user_state: finalBlindedUserState,
            intermediate_user_state_tree_roots: finalUserState,
            start_epoch_key_nonce: startEpochKeyNonce,
            end_epoch_key_nonce: endEpochKeyNonce,
            identity_pk: this.id.keypair.pubKey,
            identity_nullifier: this.id.identityNullifier,
            identity_trapdoor: this.id.identityTrapdoor,
            GST_path_elements: GSTreeProof.pathElements,
            GST_path_index: GSTreeProof.indices,
            GST_root: GSTreeRoot,
            epk_path_elements: epochKeyPathElements,
            hash_chain_results: finalHashChain,
            blinded_hash_chain_results: blindedHashChain,
            epoch_tree_root: epochTreeRoot
        })

        return {
            startTransitionProof: startTransitionProof.circuitInputs,
            processAttestationProof: processAttestationProofs,
            finalTransitionProof: finalTransitionProof,
        }
    }

    /*
     * Update transition data including latest transition epoch, GST leaf index and user state tree leaves.
     */
    public transition = (
        latestStateLeaves: IUserStateLeaf[],
    ) => {
        assert(this.hasSignedUp, "User has not signed up yet")

        const fromEpoch = this.latestTransitionedEpoch
        const transitionToEpoch = this.unirepState.currentEpoch
        const transitionToGSTIndex = this.unirepState.getNumGSTLeaves(transitionToEpoch)
        assert(fromEpoch < transitionToEpoch, "Can not transition to same epoch")

        this.latestTransitionedEpoch = transitionToEpoch
        this.latestGSTLeafIndex = transitionToGSTIndex

        // Update user state leaves
        this.latestUserStateLeaves = latestStateLeaves.slice()
    }

    public genProveReputationCircuitInputs = async (
        attesterId: BigInt,
        repNullifiersAmount: number,
        testNonceStarter: number,
        epkNonce: number,
        minRep: BigInt,
        proveGraffiti: BigInt,
        graffitiPreImage: BigInt,
    ) => {
        assert(this.hasSignedUp, "User has not signed up yet")
        assert(attesterId > BigInt(0), `attesterId must be greater than zero`)
        assert(attesterId < BigInt(2 ** this.userStateTreeDepth), `attesterId exceeds total number of attesters`)
        const epoch = this.latestTransitionedEpoch
        const epochKey = genEpochKey(this.id.identityNullifier, epoch, epkNonce)
        const rep = this.getRepByAttester(attesterId)
        const posRep = rep.posRep
        const negRep = rep.negRep
        const graffiti = rep.graffiti
        const signUp = rep.signUp
        const userStateTree = await this.genUserStateTree()
        const GSTree = this.unirepState.genGSTree(epoch)
        const GSTreeProof = GSTree.genMerklePath(this.latestGSTLeafIndex)
        const GSTreeRoot = GSTree.root
        const USTPathElements = await userStateTree.getMerkleProof(attesterId)
        const selectors: BigInt[] = []
        const nonceList: BigInt[] = []

        assert((testNonceStarter + repNullifiersAmount) <= Number(posRep) - Number(negRep), "Not enough karma to spend")
        for (let i = 0; i < repNullifiersAmount; i++) {
            nonceList.push( BigInt(testNonceStarter + i) )
            selectors.push(BigInt(1));
        }
        for (let i = repNullifiersAmount ; i < maxReputationBudget; i++) {
            nonceList.push(BigInt(0))
            selectors.push(BigInt(0))
        }

        return stringifyBigInts({
            epoch: epoch,
            epoch_key_nonce: epkNonce,
            epoch_key: epochKey,
            identity_pk: this.id.keypair.pubKey,
            identity_nullifier: this.id.identityNullifier, 
            identity_trapdoor: this.id.identityTrapdoor,
            user_tree_root: userStateTree.getRootHash(),
            GST_path_index: GSTreeProof.indices,
            GST_path_elements: GSTreeProof.pathElements,
            GST_root: GSTreeRoot,
            attester_id: attesterId,
            pos_rep: posRep,
            neg_rep: negRep,
            graffiti: graffiti,
            sign_up: signUp,
            UST_path_elements: USTPathElements,
            rep_nullifiers_amount: repNullifiersAmount,
            selectors: selectors,
            rep_nonce: nonceList,
            min_rep: minRep,
            prove_graffiti: proveGraffiti,
            graffiti_pre_image: graffitiPreImage
        })
    }
}

const getTreeDepthsForTesting = () => {
    return {
        "userStateTreeDepth": circuitUserStateTreeDepth,
        "globalStateTreeDepth": circuitGlobalStateTreeDepth,
        "epochTreeDepth": circuitEpochTreeDepth,
    }
}

const toCompleteHexString = (str: string, len?: number): string => {
    str = add0x(str)
    if (len) str = ethers.utils.hexZeroPad(str, len)
    return str
}

const genNewSMT = async (treeDepth: number, defaultLeafHash: BigInt) => {
    return SparseMerkleTreeImpl.create(
        new Keyv(),
        treeDepth,
        defaultLeafHash,
    )
}

const genNewEpochTree = async (_epochTreeDepth: number = circuitEpochTreeDepth) => {
    const defaultOTSMTHash = SMT_ONE_LEAF
    return genNewSMT(_epochTreeDepth, defaultOTSMTHash)
}

const defaultUserStateLeaf = hash5([BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)])

const computeEmptyUserStateRoot = (treeDepth: number): BigInt => {
    const t = new IncrementalQuinTree(
        treeDepth,
        defaultUserStateLeaf,
        2,
    )
    return t.root
}    

const genNewUserStateTree = async (_userStateTreeDepth: number = circuitUserStateTreeDepth) => {
    return genNewSMT(_userStateTreeDepth, defaultUserStateLeaf)
}

const genEpochKey = (identityNullifier: SnarkBigInt, epoch: number, nonce: number, _epochTreeDepth: number = circuitEpochTreeDepth): SnarkBigInt => {
    const values: any[] = [
        identityNullifier,
        epoch,
        nonce,
        BigInt(0),
        BigInt(0),
    ]
    let epochKey = hash5(values).toString()
    // Adjust epoch key size according to epoch tree depth
    const epochKeyModed = BigInt(epochKey) % BigInt(2 ** _epochTreeDepth)
    return epochKeyModed
}

const genEpochKeyNullifier = (identityNullifier: SnarkBigInt, epoch: number, nonce: number): SnarkBigInt => {
    return hash5([EPOCH_KEY_NULLIFIER_DOMAIN, identityNullifier, BigInt(epoch), BigInt(nonce), BigInt(0)])
}

const verifyProcessAttestationEvents = async(unirepContract: ethers.Contract, startBlindedUserState: BigInt | string, currentBlindedUserState: BigInt | string): Promise<boolean> => {

    const processAttestationFilter = unirepContract.filters.ProcessedAttestationsProof(currentBlindedUserState)
    const processAttestationEvents = await unirepContract.queryFilter(processAttestationFilter)
    if(processAttestationEvents.length == 0) return false

    let returnValue = false
    for(const event of processAttestationEvents){
        const args = event?.args
        const isValid = await unirepContract.verifyProcessAttestationProof(
            args?._outputBlindedUserState,
            args?._outputBlindedHashChain,
            args?._inputBlindedUserState,
            args?._proof
        )
        if(!isValid) continue
        if (BigInt(args?._inputBlindedUserState) == startBlindedUserState) {
            returnValue = true
            break
        }
        else {
            returnValue = returnValue || await verifyProcessAttestationEvents(unirepContract, startBlindedUserState, args?._inputBlindedUserState)
        }
    }
    return returnValue
}

export {
    IEpochTreeLeaf,
    Attestation,
    Reputation,
    UnirepState,
    UserState,
    SMT_ONE_LEAF,
    SMT_ZERO_LEAF,
    computeEmptyUserStateRoot,
    defaultUserStateLeaf,
    getTreeDepthsForTesting,
    genNewEpochTree,
    genNewUserStateTree,
    genNewSMT,
    toCompleteHexString,
    genEpochKey,
    genEpochKeyNullifier,
    verifyProcessAttestationEvents,
}