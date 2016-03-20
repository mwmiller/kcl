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

  test "shared secrets" do
    assert Kcl.shared_secret(ask,bpk) == sec, "Alice produces the expected secret"
    assert Kcl.shared_secret(bsk,apk) == sec, "Bob produces the same secret"
  end

  test "box/unbox with public/private pairs" do
    {boxed, _} = Kcl.box(m,n,ask,bpk)
    assert boxed == c, "Box up a packet with Alice's secret and Bob's public"
    {unboxed, _}  =  Kcl.unbox(c,n,bsk,apk)
    assert unboxed == m, "Unbox the same packet with Bob's secret and Alice's public"
  end

  test "box/unbox with connection state" do
     a_state = Kcl.new_connection_state(ask, apk, bpk)
     b_state = Kcl.new_connection_state(bsk, apk)

    {boxed, _} = Kcl.box(m,n,a_state)
    assert boxed == c, "Box up a packet with Alice's state"
    {unboxed, _}  =  Kcl.unbox(c,n,b_state)
    assert unboxed == m, "Unbox the same packet with Bob's state"
  end

end
