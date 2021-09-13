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
        Pairing.G1Point[18] IC;
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
        vk.IC[0] = Pairing.G1Point(uint256(3176875834239001116369328978657654015667988659041565528783165666838381058039),uint256(7947193074282600306033444526852043953231356044210828228767722795710743403489));
        vk.IC[1] = Pairing.G1Point(uint256(10384084965143677500142117800999800790845885695383277734429201344546352383666),uint256(6870544621903763757065455252349241602767079474891283074463968820520020752931));
        vk.IC[2] = Pairing.G1Point(uint256(13260499249966292822574814720269579057671444727645431731322675580686918693650),uint256(2423833159868152475257307127157800523801376481429569780480824172729763949850));
        vk.IC[3] = Pairing.G1Point(uint256(14420740360872222697074748282300364455079084648306695324393261910416031835668),uint256(12839924856980366937498098772114574910029149377067981382030725839771865178636));
        vk.IC[4] = Pairing.G1Point(uint256(5345341570828448729093305629417948834133737148083840573943607022426566372397),uint256(6417427538511544469084905604126145190494635335307221625326922287506486700578));
        vk.IC[5] = Pairing.G1Point(uint256(9687304500228826931622499053805004175498738653079313874294854091323763934973),uint256(3887951936100387583020809586152376142416972810702235189206017651342582116030));
        vk.IC[6] = Pairing.G1Point(uint256(8140330335784077023901824620353292059861686612389352064022512802436308705204),uint256(7730381899955664668861915351775565758941533414596449899546182617079438680557));
        vk.IC[7] = Pairing.G1Point(uint256(18536136014494281701727352959875805911953125227766606951613401962562917367995),uint256(395384605010451581943910127138388328560345071097555091051296656027008216308));
        vk.IC[8] = Pairing.G1Point(uint256(10491861171450749060509751558425305252134232123548061557741318888887238116376),uint256(20709490870985273893125838815631367787947130276414709301939870050177091733235));
        vk.IC[9] = Pairing.G1Point(uint256(12846144014304011819952580074787293756885017698469485825756971555632873054786),uint256(19127232101308071068578448099359225818980971840210050139660949434324202553217));
        vk.IC[10] = Pairing.G1Point(uint256(19136666163776857499371274775237043358388288692509827188026160848912448752015),uint256(1551897639289697377066375386699679080218033934136790184385076834565573073046));
        vk.IC[11] = Pairing.G1Point(uint256(13546024550049490040998072254892710828114233507147276753497122768411609832024),uint256(18621064589565340443357238731928697474778451839562881209375578087142053967131));
        vk.IC[12] = Pairing.G1Point(uint256(7471638924057153336839596147209740798566030791604112348049028378594441221042),uint256(13869611007089587003385928677648410290699654775425227272599087139802474823411));
        vk.IC[13] = Pairing.G1Point(uint256(14207924876915524517729049917529518441153422313706375232671198459922297615818),uint256(16449355485206710531633795081530706492387773414305663367986642422336286389208));
        vk.IC[14] = Pairing.G1Point(uint256(8392751798406806149893929742996324146761337312238195406681999131457763964986),uint256(21219822541500955491409004000707648932821560309853654395796802781769510202761));
        vk.IC[15] = Pairing.G1Point(uint256(21839040360990088332986661683391527428478266586549874334573058073207682889230),uint256(9453659862360443493422380743681671008099625944876888894842845555474860008114));
        vk.IC[16] = Pairing.G1Point(uint256(19167435521296846655673519886724483730256646151138159968990204504102624323415),uint256(5627862770415696470743978185187878859293935831137247145483414973522388827557));
        vk.IC[17] = Pairing.G1Point(uint256(18353266497418668090944185843375350979063168364294265401542298471964143189836),uint256(16524412505721927276822583840341338789104852159459044821276616410985996381860));

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
        for (uint256 i = 0; i < 17; i++) {
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