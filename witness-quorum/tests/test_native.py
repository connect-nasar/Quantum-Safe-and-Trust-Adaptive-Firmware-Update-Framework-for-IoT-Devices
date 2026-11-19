from witness.native import Native
from witness.crypto import digest


def test_no_signature_burn_matches_full_bds_transition():
    native = Native()
    public, state = native.keypair()
    for i in range(40):
        advanced = native.advance(state)
        message = bytes.fromhex(digest(str(i).encode()))
        signature, signed_state = native.sign(state, message, public)
        assert advanced == signed_state, f"BDS transition differs at {i}"
        assert native.verify(signature, message, public)
        assert not native.verify(signature, bytes(32), public)
        state = advanced


def test_reserved_final_slot_is_never_signed_or_advanced():
    native = Native()
    public, state = native.keypair()
    # Only checking the precondition; no traversal state is used at this index.
    exhausted = (1023).to_bytes(4, "big") + state[4:]
    import pytest
    with pytest.raises(ValueError): native.advance(exhausted)
    with pytest.raises(ValueError): native.sign(exhausted, bytes(32), public)


def test_disposable_state_can_burn_past_the_live_index_without_dummy_signatures():
    native = Native()
    public, state = native.keypair()
    for _ in range(321):
        state = native.advance(state)
    assert int.from_bytes(state[:4], "big") == 321
    message = bytes.fromhex(digest(b"higher-index disposable recovery test"))
    signature, after = native.sign(state, message, public)
    assert native.verify(signature, message, public)
    assert after == native.advance(state)
