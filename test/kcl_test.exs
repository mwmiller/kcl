defmodule KclTest do
  use PowerAssert
  doctest Kcl
  import PDFConstants

  test "key handling" do
    {sk, pk}  = Kcl.generate_key_pair
    assert Kcl.derive_public_key(sk) == pk, "Can reproduce a public key from a randomly generated secret key"

    assert Kcl.derive_public_key(ask) == apk, "Can reproduce Alice's public key from her secret key"
    assert Kcl.derive_public_key(bsk) == bpk, "Can reproduce Bob's public key from his secret key"

    refute Kcl.derive_public_key(apk) == ask, "Does not reproduce a secret key from a public one"
  end

  test "box/unbox with public/private pairs" do
    assert Kcl.box(m,ask,bpk,n)   == c, "Box up a packet with Alice's secret and Bob's public"
    assert Kcl.unbox(c,bsk,apk,n) == m, "Unbox the same packet with Bob's secret and Alice's public"
  end

  test "using shared_secrets" do
    assert Kcl.shared_secret(ask,bpk) == sec, "Alice produces the expected secret"
    assert Kcl.shared_secret(bsk,apk) == sec, "Bob produces the same secret"
    assert Kcl.box(m,sec,n)           == c,   "Box up a packet with the shared secret"
    assert Kcl.unbox(c,sec,n)         == m,   "Unbox it on the other end with the same secret"
  end

end
