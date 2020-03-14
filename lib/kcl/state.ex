defmodule Kcl.State do
  @moduledoc """
  On-going KCl session state

  Some helpers to maintain state between messages
  """

  defstruct our_private: nil,
            our_public: nil,
            their_public: nil,
            shared_secret: nil,
            previous_nonce: 0

  @type t :: %__MODULE__{}

  @doc """
  Initialize a new state

  The private key will be used to derive the public one, if such is
  not supplied. There is, otherwise, no verification that the supplied
  keys form a valid pair.
  """
  @spec init(Kcl.key(), Kcl.key() | nil) :: Kcl.State.t()
  def init(our_private, our_public \\ nil) do
    our_public =
      case our_public do
        nil -> Kcl.derive_public_key(our_private)
        _ -> our_public
      end

    %Kcl.State{our_private: our_private, our_public: our_public}
  end

  @doc """
  update the state for a new peer

  The shared secret is computed from the state and new peer public key.
  The previous_nonce value is also reset to `0`.
  """
  @spec new_peer(Kcl.State.t(), Kcl.key()) :: Kcl.State.t() | :error
  def new_peer(state, their_public) do
    case Kcl.shared_secret(state.our_private, their_public) do
      :error ->
        :error

      ss ->
        struct(state,
          their_public: their_public,
          shared_secret: ss,
          # Just in case someone reuses the struct.
          previous_nonce: 0
        )
    end
  end
end
