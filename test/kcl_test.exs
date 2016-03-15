defmodule KclTest do
  use PowerAssert
  doctest Kcl
  import PDFConstants

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
