# Unirep contracts v1.0.4

## Install and build
```shell
yarn install && \
yarn build
```

## Test
```shell
yarn test
```

## Utils
- `deployUnirep`
- `getUnirepContract`

## Contracts
- `Address.sol`
- `ComputeRoot.sol`
- `DomainObjs.sol`
- `EpochKeyValidityVerifier.sol`
- `Hasher.sol`
- `Poseidon.sol`
- `ProcessAttestationsVerifier.sol`
- `ReputationVerifier.sol`
- `SnarkConstants.sol`
- `StartTransitionVerifier.sol`
- `Unirep.sol`
- `UnirepParamters.sol`
- `UserSignUpVerifier.sol`
- `UserStateTransitionVerifier.sol`

## v1.0.4 Update log
- Update @unirep/circuits version
- User can prove that he has not signed up in one leaf to get airdrop
  `proveUserSignUp` circuit: change `sign_up` from private input to public input
- New paramter `uint256 userHasSignedUp;` in `UnirepParameters.sol`
- New input in `verifyUserSignUp` function