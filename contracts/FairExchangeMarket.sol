// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Groth16 verifiers exported by gnark (verifyProof reverts on failure).
interface IDecVerifier {
    function verifyProof(bytes calldata proof, uint256[4] calldata input) external view;
}

interface IEvalC1Verifier {
    function verifyProof(bytes calldata proof, uint256[7] calldata input) external view;
}

/// @title Settlement contract of the fair exchange (proof-carrying claim)
/// @notice Registration (offers with q slots, once per data commitment, and
/// Case 1 buyer keys), orders that escrow the price, and one claim per order
/// that delivers D with a proof the contract verifies before it pays: pi_dec
/// over BN254 in Case 2, and in Case 1 the blob link (BLOBHASH,
/// z = H_pt(vh || h_D), the point-evaluation precompile) followed by pi_eval
/// over BLS12-381 (EIP-2537). Anyone may send a claim; it always pays the
/// registered payout address. Refund from the refund time on, reject of an
/// open order, retire of a slot without an open order. Time is measured in
/// block numbers. Bulky values (keys, ciphertexts) stay in a
/// data-availability layer; the contract records their digests.
contract FairExchangeMarket {
    uint256 internal constant BLS_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;
    uint256 internal constant FIELD_ELEMENTS_PER_BLOB = 4096;
    address internal constant POINT_EVALUATION = address(0x0a);
    bytes internal constant TAG_PT = "fairhe/v8/H_pt";

    enum SlotState { Free, Claimed, Retired }
    enum OrderState { None, Open, Claimed, Refunded, Rejected }

    struct Offer {
        address seller;
        address payable payout;
        uint8 caseId; // 1 or 2
        bytes32 comX; // Com(x)
        uint256 price;
        uint64 tMin; // bounds on T_ref - T_order, in blocks
        uint64 tMax;
        uint16 q; // slots 1..q
        bytes32 terms; // digest of the terms (class, input range, scheme, sigma_fl, tau)
        bytes32 claimVk; // VK ID of the on-chain proof of the claim
        bytes32 keyVk; // VK IDs the counterparty checks off-chain
        bytes32 inputVk;
    }

    struct Slot {
        SlotState state;
        uint256 openOrder; // the last order of the slot (0 = none)
        bytes32 hPk; // Case 2: digest of the session public key
        bytes32 hC1; // Case 2: digest of c_1
        bytes32 hS; // Case 2: h_s
    }

    struct BuyerKey {
        address owner;
        uint64 keyIndex; // a of pk_B is H_coin(owner || keyIndex)
        bytes32 hPk; // digest of pk_B
        bytes32 hSB; // salted digest of s_B
    }

    struct Order {
        uint256 offerId;
        uint16 slot;
        address payable buyer;
        uint256 amount;
        uint64 tOrder;
        uint64 tRef;
        bytes32 comF;
        bytes32 hInput; // Case 1: h_c of the ordered ciphertext; Case 2: h_c21
        bytes32 hKey; // Case 1: h_pk of the buyer's registered key
        OrderState state;
    }

    // Verification keys fixed at deployment: on-chain verifiers by VK ID, and
    // the VK IDs of the off-chain proofs.
    mapping(bytes32 => address) public verifierOf;
    mapping(bytes32 => bool) public offchainVk;

    uint256 public offerCount;
    uint256 public orderCount;
    mapping(uint256 => Offer) internal offers;
    mapping(uint256 => mapping(uint16 => Slot)) internal slots;
    mapping(bytes32 => BuyerKey) public buyerKeys; // keyId = keccak256(buyer, keyIndex)
    mapping(uint256 => Order) public orders;
    // The offer of each data commitment: the budget of q slots is per Com(x).
    mapping(bytes32 => uint256) public offerOfCom;

    event OfferRegistered(uint256 indexed offerId, address indexed seller, uint8 caseId, bytes32 comX, uint16 q);
    event KeyRegistered(bytes32 indexed keyId, address indexed buyer, bytes32 hPk, bytes32 hSB);
    event Ordered(
        uint256 indexed orderId, uint256 indexed offerId, uint16 slot, address buyer, uint64 tRef, bytes32 hInput, bytes32 keyId
    );
    /// p is the Case 2 deliverable (0 in Case 1); versionedHash and hD name
    /// the blob of the Case 1 deliverable (0 in Case 2).
    event Claimed(uint256 indexed orderId, uint256 p, bytes32 versionedHash, bytes32 hD);
    event Refunded(uint256 indexed orderId);
    event Rejected(uint256 indexed orderId);
    event Retired(uint256 indexed offerId, uint16 slot);

    error ComRegistered();
    error NotSeller();
    error BadSlot();
    error SlotBusy();
    error BadRefundTime();
    error BadPayment();
    error NotOpen();
    error TooLate();
    error TooEarly();
    error UnknownVk();
    error NoBlob();
    error PointEvaluationFailed();
    error WrongCase();
    error UnknownKey();

    constructor(bytes32[] memory claimVkIds, address[] memory verifiers, bytes32[] memory offchainVkIds) {
        require(claimVkIds.length == verifiers.length, "lengths");
        for (uint256 i = 0; i < claimVkIds.length; i++) {
            verifierOf[claimVkIds[i]] = verifiers[i];
        }
        for (uint256 i = 0; i < offchainVkIds.length; i++) {
            offchainVk[offchainVkIds[i]] = true;
        }
    }

    // ------------------------------------------------------------------
    // Registration

    struct OfferArgs {
        uint8 caseId;
        address payable payout;
        bytes32 comX;
        uint256 price;
        uint64 tMin;
        uint64 tMax;
        uint16 q;
        bytes32 terms;
        bytes32 claimVk;
        bytes32 keyVk;
        bytes32 inputVk;
    }

    /// @notice Seller registration, once per data commitment: Com(x), the
    /// terms and q slots. In Case 2 each slot carries the digests of its
    /// session key, its c_1 and h_s.
    function registerOffer(OfferArgs calldata a, bytes32[] calldata hPk, bytes32[] calldata hC1, bytes32[] calldata hS)
        external
        returns (uint256 offerId)
    {
        if (a.caseId != 1 && a.caseId != 2) revert WrongCase();
        if (offerOfCom[a.comX] != 0) revert ComRegistered();
        if (verifierOf[a.claimVk] == address(0)) revert UnknownVk();
        if (!offchainVk[a.keyVk] || !offchainVk[a.inputVk]) revert UnknownVk();
        require(a.tMin <= a.tMax && a.tMax > 0, "time bounds");
        uint16 q = a.q;
        require(q > 0, "slots");
        if (a.caseId == 2) {
            require(hPk.length == q && hC1.length == q && hS.length == q, "slot digests");
        } else {
            require(hPk.length == 0 && hC1.length == 0 && hS.length == 0, "Case 1 slots carry no keys");
        }
        offerId = ++offerCount;
        offerOfCom[a.comX] = offerId;
        offers[offerId] = Offer({
            seller: msg.sender,
            payout: a.payout,
            caseId: a.caseId,
            comX: a.comX,
            price: a.price,
            tMin: a.tMin,
            tMax: a.tMax,
            q: q,
            terms: a.terms,
            claimVk: a.claimVk,
            keyVk: a.keyVk,
            inputVk: a.inputVk
        });
        if (a.caseId == 2) {
            for (uint16 i = 0; i < q; i++) {
                Slot storage s = slots[offerId][i + 1];
                s.hPk = hPk[i];
                s.hC1 = hC1[i];
                s.hS = hS[i];
            }
        }
        emit OfferRegistered(offerId, msg.sender, a.caseId, a.comX, q);
    }

    /// @notice Case 1 buyer registration of an HE key (pi_key is checked by
    /// the seller off-chain against the key fetched by its digest).
    function registerKey(uint64 keyIndex, bytes32 hPk, bytes32 hSB) external returns (bytes32 keyId) {
        keyId = keccak256(abi.encodePacked(msg.sender, keyIndex));
        require(buyerKeys[keyId].owner == address(0), "key exists");
        buyerKeys[keyId] = BuyerKey({owner: msg.sender, keyIndex: keyIndex, hPk: hPk, hSB: hSB});
        emit KeyRegistered(keyId, msg.sender, hPk, hSB);
    }

    // ------------------------------------------------------------------
    // Order

    /// @notice Escrows the price for slot i with refund time tRef. hInput is
    /// h_c (Case 1) or h_c21 (Case 2); keyId names the buyer's registered key
    /// in Case 1.
    function order(uint256 offerId, uint16 slot, uint64 tRef, bytes32 comF, bytes32 hInput, bytes32 keyId)
        external
        payable
        returns (uint256 orderId)
    {
        Offer storage o = offers[offerId];
        if (o.seller == address(0) || slot == 0 || slot > o.q) revert BadSlot();
        Slot storage s = slots[offerId][slot];
        if (s.state != SlotState.Free) revert BadSlot();
        if (s.openOrder != 0) {
            Order storage prev = orders[s.openOrder];
            if (prev.state == OrderState.Open && block.number < prev.tRef) revert SlotBusy();
        }
        if (tRef < block.number + o.tMin || tRef > block.number + o.tMax) revert BadRefundTime();
        if (msg.value != o.price) revert BadPayment();
        bytes32 hKey;
        if (o.caseId == 1) {
            BuyerKey storage k = buyerKeys[keyId];
            if (k.owner != msg.sender) revert UnknownKey();
            hKey = k.hPk;
        }
        orderId = ++orderCount;
        orders[orderId] = Order({
            offerId: offerId,
            slot: slot,
            buyer: payable(msg.sender),
            amount: msg.value,
            tOrder: uint64(block.number),
            tRef: tRef,
            comF: comF,
            hInput: hInput,
            hKey: hKey,
            state: OrderState.Open
        });
        s.openOrder = orderId;
        emit Ordered(orderId, offerId, slot, msg.sender, tRef, hInput, keyId);
    }

    // ------------------------------------------------------------------
    // Claim

    /// @notice Case 2 claim: the partial decryption p with pi_dec.
    function claimDec(uint256 orderId, uint256 p, bytes calldata proof) external {
        (Order storage od, Offer storage o, Slot storage s) = _claimable(orderId, 2);
        uint256[4] memory input = [orderId, uint256(od.hInput), uint256(s.hS), p];
        IDecVerifier(verifierOf[o.claimVk]).verifyProof(proof, input);
        _pay(od, o, s);
        emit Claimed(orderId, p, bytes32(0), bytes32(0));
    }

    /// The Case 1 deliverable's link: its digest h_D, the value y_z of the
    /// blob polynomial at z, and the KZG commitment and opening proof.
    struct BlobClaim {
        bytes32 hD;
        uint256 yZ;
        bytes commitment;
        bytes kzgProof;
    }

    /// @notice Case 1 claim, carried by a blob transaction: h_D, the opening
    /// of the blob at z = H_pt(vh || h_D) to y_z, and pi_eval.
    function claimBlob(uint256 orderId, BlobClaim calldata c, bytes calldata proof) external {
        (Order storage od, Offer storage o, Slot storage s) = _claimable(orderId, 1);
        (bytes32 vh, uint256 z) = _blobLink(c);
        _verifyEval(orderId, od, o, c.hD, z, c.yZ, proof);
        _pay(od, o, s);
        emit Claimed(orderId, 0, vh, c.hD);
    }

    /// @dev The blob link: vh = blobhash(0), z = H_pt(vh || h_D) mod r_bls,
    /// and the KZG opening of the blob at z to y_z.
    function _blobLink(BlobClaim calldata c) internal view returns (bytes32 vh, uint256 z) {
        vh = blobhash(0);
        if (vh == bytes32(0)) revert NoBlob();
        z = uint256(keccak256(abi.encodePacked(TAG_PT, vh, c.hD))) % BLS_MODULUS;
        _pointEvaluation(vh, z, c.yZ, c.commitment, c.kzgProof);
    }

    /// @dev pi_eval with public inputs (order ID, h_c, h_pk, Com(x), h_D, z, y_z).
    function _verifyEval(
        uint256 orderId,
        Order storage od,
        Offer storage o,
        bytes32 hD,
        uint256 z,
        uint256 yZ,
        bytes calldata proof
    ) internal view {
        uint256[7] memory input;
        input[0] = orderId;
        input[1] = uint256(od.hInput);
        input[2] = uint256(od.hKey);
        input[3] = uint256(o.comX);
        input[4] = uint256(hD);
        input[5] = z;
        input[6] = yZ;
        IEvalC1Verifier(verifierOf[o.claimVk]).verifyProof(proof, input);
    }

    /// @dev Any sender may claim: the payment goes to the registered payout
    /// address and the proof is bound to the order, so a copied pending claim
    /// neither redirects the payment nor settles another order.
    function _claimable(uint256 orderId, uint8 caseId)
        internal
        view
        returns (Order storage od, Offer storage o, Slot storage s)
    {
        od = orders[orderId];
        if (od.state != OrderState.Open) revert NotOpen();
        o = offers[od.offerId];
        if (o.caseId != caseId) revert WrongCase();
        if (block.number >= od.tRef) revert TooLate();
        s = slots[od.offerId][od.slot];
        if (s.state != SlotState.Free) revert BadSlot();
    }

    function _pay(Order storage od, Offer storage o, Slot storage s) internal {
        od.state = OrderState.Claimed;
        s.state = SlotState.Claimed;
        uint256 amount = od.amount;
        od.amount = 0;
        (bool ok,) = o.payout.call{value: amount}("");
        require(ok, "payout");
    }

    /// @dev EIP-4844 point evaluation: versioned_hash | z | y | commitment | proof.
    function _pointEvaluation(bytes32 vh, uint256 z, uint256 y, bytes calldata commitment, bytes calldata kzgProof)
        internal
        view
    {
        require(commitment.length == 48 && kzgProof.length == 48, "kzg lengths");
        (bool ok, bytes memory out) =
            POINT_EVALUATION.staticcall(abi.encodePacked(vh, z, y, commitment, kzgProof));
        if (!ok || out.length != 64) revert PointEvaluationFailed();
        (uint256 width, uint256 modulus) = abi.decode(out, (uint256, uint256));
        if (width != FIELD_ELEMENTS_PER_BLOB || modulus != BLS_MODULUS) revert PointEvaluationFailed();
    }

    // ------------------------------------------------------------------
    // Refund, reject, retire

    /// @notice From the refund time on, without a successful claim.
    function refund(uint256 orderId) external {
        Order storage od = orders[orderId];
        if (od.state != OrderState.Open) revert NotOpen();
        if (block.number < od.tRef) revert TooEarly();
        od.state = OrderState.Refunded;
        uint256 amount = od.amount;
        od.amount = 0;
        (bool ok,) = od.buyer.call{value: amount}("");
        require(ok, "refund");
        emit Refunded(orderId);
    }

    /// @notice The seller returns the escrow of an open order at once: before
    /// any claim and before the refund time.
    function reject(uint256 orderId) external {
        Order storage od = orders[orderId];
        if (od.state != OrderState.Open) revert NotOpen();
        if (msg.sender != offers[od.offerId].seller) revert NotSeller();
        if (block.number >= od.tRef) revert TooLate();
        od.state = OrderState.Rejected;
        uint256 amount = od.amount;
        od.amount = 0;
        (bool ok,) = od.buyer.call{value: amount}("");
        require(ok, "reject");
        emit Rejected(orderId);
    }

    /// @notice The seller marks an unclaimed slot without an open order
    /// unusable (e.g. after a claim that was broadcast but not included); an
    /// open order must be rejected first. The escrow of an order whose refund
    /// time has passed stays with its buyer's refund.
    function retire(uint256 offerId, uint16 slot) external {
        Offer storage o = offers[offerId];
        if (msg.sender != o.seller) revert NotSeller();
        if (slot == 0 || slot > o.q) revert BadSlot();
        Slot storage s = slots[offerId][slot];
        if (s.state == SlotState.Claimed) revert BadSlot();
        if (s.openOrder != 0) {
            Order storage od = orders[s.openOrder];
            if (od.state == OrderState.Open && block.number < od.tRef) revert SlotBusy();
        }
        s.state = SlotState.Retired;
        emit Retired(offerId, slot);
    }

    // ------------------------------------------------------------------
    // Views

    function offer(uint256 offerId) external view returns (Offer memory) {
        return offers[offerId];
    }

    function slotOf(uint256 offerId, uint16 slot) external view returns (Slot memory) {
        return slots[offerId][slot];
    }
}
