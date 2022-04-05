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

contract UserStateTransitionVerifier {

    using Pairing for *;

    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[13] IC;
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
        vk.IC[0] = Pairing.G1Point(uint256(1158623942304341524136608806695116396578814544683923194244259694667558641801),uint256(12647966121293498517198656708441934970392323085384217914900727867880723522156));
        vk.IC[1] = Pairing.G1Point(uint256(6065508479998955321696432430752306823048638835418998026775615656368915442786),uint256(16071777738203901831187984479684339246040820616555515474949782973588372026627));
        vk.IC[2] = Pairing.G1Point(uint256(19964365829378564799245478718303769271881341952585064002030032093305890308869),uint256(17505594350621535266233117666349930298328538240474347105092245688950001383437));
        vk.IC[3] = Pairing.G1Point(uint256(20208066692250753198374221005988573271283545979944078987150836693753478798944),uint256(6228223513386106144149495528250393467009203641447609371199072615246344927797));
        vk.IC[4] = Pairing.G1Point(uint256(3003849469966794978213405128264279846328788975065356832136262130201646815150),uint256(11861033138684427822548999306366590209167050064064959405912571087297053705121));
        vk.IC[5] = Pairing.G1Point(uint256(6406272883690976569560983581104198011139765331372659896934195424144959224455),uint256(11493150363345575635939387788323615645674214832899511357568360578113295234468));
        vk.IC[6] = Pairing.G1Point(uint256(4720555705554158398662293420746602789716277262411727238686443435293561076922),uint256(11391352759145478618914254244923669114679399724343534717903977288253475795591));
        vk.IC[7] = Pairing.G1Point(uint256(14148328056524404419445703755963613189647787951604864792755593780749736990724),uint256(18270887195826976956762057096577584105729389191562498718630407811040715129396));
        vk.IC[8] = Pairing.G1Point(uint256(5071086891208653720706685769621924904133273239525696959025540084051265701259),uint256(18685134678948884864136082176290563357699424747374240721175137097104019550393));
        vk.IC[9] = Pairing.G1Point(uint256(4563250733174964124409921800289500547372391887915960422221458277256014271076),uint256(10945862822355565962905758192839995696320459010743183276460034325993399264575));
        vk.IC[10] = Pairing.G1Point(uint256(6882662481496183328202920741818172489610447185733299151629928745156986422690),uint256(6473213505257364551170105543801826468115231798669632972936832455618853713411));
        vk.IC[11] = Pairing.G1Point(uint256(12947047719279932825185100946735759080962604888584243206840832653759239734492),uint256(16341968759523271788554108291971231806536226557021983107268572931847834055615));
        vk.IC[12] = Pairing.G1Point(uint256(21044440962957581887404914027000616461424192541277828655780308131306512417466),uint256(17156391799516970932400213171372449520824002161158360427524285674407929119969));

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
        for (uint256 i = 0; i < 12; i++) {
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