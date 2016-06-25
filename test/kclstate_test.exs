defmodule KclStateTest do
  use ExUnit.Case
  import PDFConstants

  test "init" do
    newly_minted = %Kcl.State{our_private:    ask,
                              our_public:     apk,
                              their_public:   nil,
                              shared_secret:  nil,
                              previous_nonce: 0,
                             }

    assert Kcl.State.init(ask)      == newly_minted, "Can init from just our secret key"
    assert Kcl.State.init(ask, apk) == newly_minted, "init from both private and public"
  end

  test "new peer" do
    newly_peered = %Kcl.State{our_private:    ask,
                              our_public:     apk,
                              their_public:   bpk,
                              shared_secret:  sec,
                              previous_nonce: 0,
                             }

    assert Kcl.State.init(ask) |> Kcl.State.new_peer(bpk) == newly_peered, "Brand new peering looks as expected"
  end

end
