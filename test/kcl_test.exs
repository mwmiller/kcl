defmodule KclTest do
  use ExUnit.Case
  doctest Kcl
  import PDFConstants

  test "key handling" do
    {ssk, spk} = Kcl.generate_key_pair(:sign)
    {esk, epk} = {Kcl.sign_to_encrypt(ssk, :secret), Kcl.sign_to_encrypt(spk, :public)}

    assert Kcl.derive_public_key(esk, :encrypt) == epk,
           "Can reproduce a public encryption key from a randomly generated secret key"

    assert Kcl.derive_public_key(ssk, :sign) == spk,
           "Can reproduce a public signing key from a randomly generated secret key"

    refute Kcl.derive_public_key(esk, :sign) == spk,
           "Public encryption key is not the public signing key"

    refute Kcl.derive_public_key(ssk, :encrypt) == spk,
           "Public signing key is not the public encryption key"

    assert Kcl.derive_public_key(ask()) == apk(),
           "Can reproduce Alice's public key from her secret key"

    assert Kcl.derive_public_key(bsk()) == bpk(),
           "Can reproduce Bob's public key from his secret key"

    refute Kcl.derive_public_key(apk()) == ask(),
           "Does not reproduce a secret key from a public one"
  end

  test "shared secrets" do
    assert Kcl.shared_secret(ask(), bpk()) == sec(), "Alice produces the expected secret"
    assert Kcl.shared_secret(bsk(), apk()) == sec(), "Bob produces the same secret"
    assert Kcl.shared_secret("", apk()) == :error, "Returns error on empty secret"
    assert Kcl.shared_secret(ask(), "") == :error, "Returns error on empty public"
  end

  test "box/unbox with public/private pairs" do
    {boxed, _} = Kcl.box(m(), n(), ask(), bpk())
    assert boxed == c(), "Box up a packet with Alice's secret and Bob's public"
    {unboxed, _} = Kcl.unbox(c(), n(), bsk(), apk())
    assert unboxed == m(), "Unbox the same packet with Bob's secret and Alice's public"
  end

  test "box/unbox with connection state" do
    a_state = Kcl.new_connection_state(ask(), apk(), bpk())
    b_state = Kcl.new_connection_state(bsk(), apk())

    {boxed, _} = Kcl.box(m(), n(), a_state)
    assert boxed == c(), "Box up a packet with Alice's state"
    {unboxed, _} = Kcl.unbox(c(), n(), b_state)
    assert unboxed == m(), "Unbox the same packet with Bob's state"
  end

  test "message signatures" do
    {ssk, spk} = Kcl.generate_key_pair(:sign)
    msg = :crypto.strong_rand_bytes(384)

    sig = Kcl.sign(msg, ssk, spk)

    assert byte_size(sig) == 64, "Generates a 64-byte signature"
    assert Kcl.valid_signature?(sig, msg, spk), "The signature can be validated"
  end

  test "auth roundtrip" do
    {_ssk, spk} = Kcl.generate_key_pair(:encrypt)
    msg = :crypto.strong_rand_bytes(384)
    hmac = Kcl.auth(msg, spk)
    assert byte_size(hmac) == 32, "Generates a 32-byte HMAC"
    assert Kcl.valid_auth?(hmac, msg, spk), "The HMAC can be validated"
  end
end
