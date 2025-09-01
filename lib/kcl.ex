defmodule Kcl do
  @moduledoc """
  pure Elixir NaCl crypto suite substitute

  The `box` and `unbox` functions exposed here are the equivalent
  of NaCl's:

  - `crypto_box_curve25519xsalsa20poly1305`
  - `crypto_box_curve25519xsalsa20poly1305_open`
  """

  @typedoc """
  shared nonce
  """
  @type nonce :: binary

  @typedoc """
  public or private key
  """
  @type key :: binary

  @typedoc """
  computed signature
  """
  @type signature :: binary

  @typedoc """
  key varieties
  """
  @type key_variety :: :sign | :encrypt

  @typedoc """
  key visibility
  """
  @type key_vis :: :public | :secret

  defp first_level_key(k), do: k |> pad(16) |> Salsa20.hash(sixteen_zeroes())

  defp second_level_key(k, n) when byte_size(n) == 24,
    do: k |> Salsa20.hash(binary_part(n, 0, 16))

  defp pad(s, n) when byte_size(s) >= n, do: s
  defp pad(s, n) when byte_size(s) < n, do: pad(<<0>> <> s, n)

  defp sixteen_zeroes, do: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
  defp thirtytwo_zeroes, do: sixteen_zeroes() <> sixteen_zeroes()

  @doc """
  generate a `{private, public}` key pair

  """
  @spec generate_key_pair(key_variety) :: {key, key} | :error
  def generate_key_pair(variety \\ :encrypt)
  def generate_key_pair(:encrypt), do: Curve25519.generate_key_pair()
  def generate_key_pair(:sign), do: Ed25519.generate_key_pair()

  @doc """
  derive a public key from a private key
  """
  @spec derive_public_key(key, key_variety) :: key | :error
  def derive_public_key(private_key, variety \\ :encrypt)
  def derive_public_key(private_key, :encrypt), do: Curve25519.derive_public_key(private_key)
  def derive_public_key(private_key, :sign), do: Ed25519.derive_public_key(private_key)

  @doc """
  convert a signing Ed25519 key to a Curve25519 encryption key
  """
  @spec sign_to_encrypt(key, key_vis) :: key
  def sign_to_encrypt(key, which), do: Ed25519.to_curve25519(key, which)

  @doc """
  pre-compute a shared key

  Mainly useful in a situation where many messages will be exchanged.
  """
  def shared_secret(our_private, their_public) do
    case Curve25519.derive_shared_secret(our_private, their_public) do
      :error -> :error
      val -> first_level_key(val)
    end
  end

  @doc """
  box up an authenticated packet

  """
  @spec box(binary, nonce, key, key) :: {binary, Kcl.State.t()}
  def box(msg, nonce, our_private, their_public),
    do: box(msg, nonce, our_private |> Kcl.State.init() |> Kcl.State.new_peer(their_public))

  @spec box(binary, nonce, Kcl.State.t()) :: {binary, Kcl.State.t()}
  def box(msg, nonce, state) when is_map(state),
    do: {secretbox(msg, nonce, state.shared_secret), struct(state, previous_nonce: nonce)}

  @spec secretbox(binary, nonce, key) :: binary
  @doc """
  box based on a shared secret
  """
  def secretbox(msg, nonce, key) do
    <<pnonce::binary-size(32), c::binary>> =
      Salsa20.crypt(
        thirtytwo_zeroes() <> msg,
        second_level_key(key, nonce),
        binary_part(nonce, 16, 8)
      )

    Poly1305.hmac(c, pnonce) <> c
  end

  @doc """
  unbox an authenticated packet

  Returns `{:error, reason}` when the packet contents cannot be authenticated, otherwise
  the decrypted payload and updated state.
  """
  @spec unbox(binary, nonce, key, key) :: {binary, Kcl.State.t()} | {:error, String.t()}
  def unbox(packet, nonce, our_private, their_public),
    do:
      packet |> unbox(nonce, our_private |> Kcl.State.init() |> Kcl.State.new_peer(their_public))

  def unbox(packet, nonce, state) do
    case {nonce > state.previous_nonce, secretunbox(packet, nonce, state.shared_secret)} do
      {false, _} -> {:error, "nonce"}
      {true, :error} -> {:error, "decode"}
      {true, m} -> {m, struct(state, previous_nonce: nonce)}
    end
  end

  @doc """
  unbox based on a shared secret
  """
  @spec secretunbox(binary, nonce, key) :: binary | :error
  def secretunbox(packet, nonce, key)

  def secretunbox(<<mac::binary-size(16), c::binary>>, nonce, key) do
    <<pnonce::binary-size(32), m::binary>> =
      Salsa20.crypt(
        thirtytwo_zeroes() <> c,
        second_level_key(key, nonce),
        binary_part(nonce, 16, 8)
      )

    case c |> Poly1305.hmac(pnonce) |> Poly1305.same_hmac?(mac) do
      true -> m
      _ -> :error
    end
  end

  @doc """
  create an inital state for a peer connection

  A convenience wrapper around `Kcl.State.init` and `Kcl.State.new_peer`
  """
  @spec new_connection_state(key, key | nil, key) :: Kcl.State.t()
  def new_connection_state(our_private, our_public \\ nil, their_public) do
    our_private |> Kcl.State.init(our_public) |> Kcl.State.new_peer(their_public)
  end

  @doc """
  sign a message

  If only the secret key is provided, the public key will be derived therefrom.
  This can add significant overhead to the signing operation.
  """
  @spec sign(binary, key, key) :: signature
  def sign(message, secret_key, public_key \\ nil),
    do: Ed25519.signature(message, secret_key, public_key)

  @doc """
  validate a message signature
  """
  @spec valid_signature?(signature, binary, key) :: boolean
  def valid_signature?(signature, message, public_key),
    do: Ed25519.valid_signature?(signature, message, public_key)

  @doc """
  `crypto_auth` equivalent
  """
  @spec auth(binary, key) :: signature
  def auth(message, key),
    do: :crypto.macN(:hmac, :sha512, :binary.bin_to_list(key), :binary.bin_to_list(message), 32)

  @doc """
  Compare `auth` HMAC
  """
  @spec valid_auth?(signature, binary, key) :: boolean
  def valid_auth?(signature, message, key),
    do: auth(message, key) |> Equivalex.equal?(signature)
end
