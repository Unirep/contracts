// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// 2019 OKIMS

pragma solidity ^0.8.0;

library Pairing {

    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero. 
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {

        // The prime q in the base field F_q for G1
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
        }
    }

    /*
     * @return The sum of two points of G1
     */
    function plus(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {

        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-add-failed");
    }

    /*
     * @return The product of a point on G1 and a scalar, i.e.
     *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     *         points p.
     */
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {

        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success,"pairing-mul-failed");
    }

    /* @return The result of computing the pairing check
     *         e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
     *         For example,
     *         pairing([P1(), P1().negate()], [P2(), P2()]) should return true.
     */
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {

        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];

        uint256 inputSize = 24;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 4; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-opcode-failed");

        return out[0] != 0;
    }
}

contract ReputationVerifier {

    using Pairing for *;

    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[19] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alpha1 = Pairing.G1Point(uint256(20491192805390485299153009773594534940189261866228447918068658471970481763042),uint256(9383485363053290200918347156157836566562967994039712273449902621266178545958));
        vk.beta2 = Pairing.G2Point([uint256(4252822878758300859123897981450591353533073413197771768651442665752259397132),uint256(6375614351688725206403948262868962793625744043794305715222011528459656738731)], [uint256(21847035105528745403288232691147584728191162732299865338377159692350059136679),uint256(10505242626370262277552901082094356697409835680220590971873171140371331206856)]);
        vk.gamma2 = Pairing.G2Point([uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781)], [uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)]);
        vk.delta2 = Pairing.G2Point([uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781)], [uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)]);
        vk.IC[0] = Pairing.G1Point(uint256(2301449007413289266717980809229756159437849129500539963450034383925655960896),uint256(8418113927342004457593584532279449702670034958411272903424000168671980678311));
        vk.IC[1] = Pairing.G1Point(uint256(3221160705336570197117350996560252594864690874908819872615175860014249574780),uint256(933876500610599788732407311177561679374731116351413388487171880141445148710));
        vk.IC[2] = Pairing.G1Point(uint256(2832773544274635049924578498498607843856135693427225814002520514689060512450),uint256(14357059151578472667435090684228464307259599322678197428683723260805960940815));
        vk.IC[3] = Pairing.G1Point(uint256(6659294854038099833414783045294993487451847299082197578383606809164072888725),uint256(872418517834420281286498524997914435123639132500259456509806975223391110176));
        vk.IC[4] = Pairing.G1Point(uint256(4073077486473922004922142506326592904892026917135390626206782335724633145050),uint256(17792464573293788212567272462336955529259839546260496616051089326762996921753));
        vk.IC[5] = Pairing.G1Point(uint256(15443387187589411036734118111968960445632260677425151126350377758594141390175),uint256(1864283780624559555358975349136581028524393925962591279290193340959172954496));
        vk.IC[6] = Pairing.G1Point(uint256(8164098210540393974172895514142779352382373809339512481996173232976954550526),uint256(6686226249569810249010591338773400120747201844482284274578841419659147390275));
        vk.IC[7] = Pairing.G1Point(uint256(11182261845189553147564965075610936251135076960682624040491465833949207097747),uint256(8118126141788750214848388745723937766372344797379008566425251846778143940149));
        vk.IC[8] = Pairing.G1Point(uint256(6081470780544331128055217339879322559979748073231533764966381319731736456547),uint256(20389136346850149518862978529176245222619619939238081715085618505329506280769));
        vk.IC[9] = Pairing.G1Point(uint256(9606590567495720446753247558665184011778196514022605979191622627191185825165),uint256(8122411507518284062637019222014233018095385297586184796762110792128099078900));
        vk.IC[10] = Pairing.G1Point(uint256(8759060774856126447946727394680325118760803129933208146641400053473287330626),uint256(7236581375036378884314190321380509093102569274742230815252279707010123523966));
        vk.IC[11] = Pairing.G1Point(uint256(1144995681354865132770063751524207767763935783310275007389271605815504416480),uint256(428905524228587749600506518649044015743248308865065426194743680419648001444));
        vk.IC[12] = Pairing.G1Point(uint256(18141083063721300232437063871720509414773556208209320114513741572552289639546),uint256(14678090267325055995789907096133445653548465927454537609729949757150591267029));
        vk.IC[13] = Pairing.G1Point(uint256(6543368682452592390728361235894469569574294249933576517105273612855406858630),uint256(21004699573787861353696203939541269297488401332308649646317579436502727113032));
        vk.IC[14] = Pairing.G1Point(uint256(4883976707819603207054458858404110903483369982273405467095608837941005282344),uint256(6352819686586986649919495211453753164645889292456237466139397391249277515958));
        vk.IC[15] = Pairing.G1Point(uint256(14224292585110701694869939679436603661573932984860943973352033985528594628964),uint256(19048772547012323689921875130902945926488605034696014505187550962227532343507));
        vk.IC[16] = Pairing.G1Point(uint256(18040954004158966146632437675829323481683827915920582294567269524962991578619),uint256(884594711288277792743153118163535690305548872106460200078310094657691783922));
        vk.IC[17] = Pairing.G1Point(uint256(8482769933362233861390675714519644880375471206900596370810548611708752234651),uint256(6192315765027149419668571704931616302119680373726021221917207702853804846956));
        vk.IC[18] = Pairing.G1Point(uint256(18132718800115322264747269250514906321278157282856073939773951685310946876133),uint256(10549192883434972730618853513178620105214541280489577766520611662808911975917));

    }
    
    /*
     * @returns Whether the proof is valid given the hardcoded verifying key
     *          above and the public inputs
     */
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] memory input
    ) public view returns (bool) {

        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);

        VerifyingKey memory vk = verifyingKey();

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);

        // Make sure that proof.A, B, and C are each less than the prime q
        require(proof.A.X < PRIME_Q, "verifier-aX-gte-prime-q");
        require(proof.A.Y < PRIME_Q, "verifier-aY-gte-prime-q");

        require(proof.B.X[0] < PRIME_Q, "verifier-bX0-gte-prime-q");
        require(proof.B.Y[0] < PRIME_Q, "verifier-bY0-gte-prime-q");

        require(proof.B.X[1] < PRIME_Q, "verifier-bX1-gte-prime-q");
        require(proof.B.Y[1] < PRIME_Q, "verifier-bY1-gte-prime-q");

        require(proof.C.X < PRIME_Q, "verifier-cX-gte-prime-q");
        require(proof.C.Y < PRIME_Q, "verifier-cY-gte-prime-q");

        // Make sure that every input is less than the snark scalar field
        //for (uint256 i = 0; i < input.length; i++) {
        for (uint256 i = 0; i < 18; i++) {
            require(input[i] < SNARK_SCALAR_FIELD,"verifier-gte-snark-scalar-field");
            vk_x = Pairing.plus(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }

        vk_x = Pairing.plus(vk_x, vk.IC[0]);

        return Pairing.pairing(
            Pairing.negate(proof.A),
            proof.B,
            vk.alpha1,
            vk.beta2,
            vk_x,
            vk.gamma2,
            proof.C,
            vk.delta2
        );
    }
}