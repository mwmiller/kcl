defmodule Kcl do

  @moduledoc """
  A poor NaCl crypto suite substitute

  The functions exposed here are the equivalent of (and
  interoperable with):

  - `crypto_box_curve25519xsalsa20poly1305`
  - `crypto_box_curve25519xsalsa20poly1305_open`

  At this time, no support is provided for multiple packets/streaming
  or nonce-agreement.
  """

  @typedoc """
  shared nonce
  """
  @type nonce :: <<_ :: 24 * 8>>

  @typedoc """
  public or private key
  """
  @type key :: <<_ :: 32 * 8>>

  defp first_level_key(k), do: Salsa20.hash(k, sixteen_zeroes)
  defp second_level_key(k,n) when byte_size(n) == 24, do: k |> Salsa20.hash(binary_part(n,0,16))

  defp sixteen_zeroes,   do: <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>
  defp thirtytwo_zeroes, do: sixteen_zeroes<>sixteen_zeroes

  @doc """
  generate a private/public key pair
  """
  @spec generate_key_pair() :: {key, key} | :error
  def generate_key_pair, do: Curve25519.generate_key_pair

  @doc """
  derive a public key from a private key
  """
  @spec derive_public_key(key) :: key | :error
  def derive_public_key(private_key), do: Curve25519.derive_public_key(private_key)

  @doc """
  pre-compute a shared key

  Mainly useful in a situation where many messages will be exchanged.
  This module does not yet do a lot of support in that area.
  """
  def shared_secret(our_private, their_public), do: Curve25519.derive_shared_secret(our_private,their_public) |> first_level_key

  @doc """
  box up an authenticated packet

  `box/3` uses the result of `shared_secret`
  `box/4` will recompute this key from the parties' secret and public keys.
  """
  @spec box(binary, key, key, nonce) :: binary
  def box(msg,our_private,their_public,nonce) do
      shared_secret = shared_secret(our_private, their_public)
      box(msg,shared_secret,nonce)
  end
  @spec box(binary,key,nonce) :: binary
  def box(msg,shared_secret,nonce) do
      <<pnonce::binary-size(32), c::binary>> =  Salsa20.crypt(thirtytwo_zeroes<>msg,second_level_key(shared_secret,nonce),binary_part(nonce,16,8))
      Poly1305.hmac(c,pnonce)<>c
  end

  @doc """
  unbox an authenticated packet

  Returns `:error` when the packet contents cannot be authenticated, otherwise
  the decrypted payload.

  `unbox/3` uses the pre-computed keys from `shared_secret`
  `unbox/4` recomputes the shared key from the parties' secret and public keys
  """
  @spec unbox(binary, key, key, nonce) :: binary | :error
  def unbox(packet,our_private,their_public,nonce) do
      shared_secret = shared_secret(our_private,their_public)
      unbox(packet,shared_secret,nonce)
  end
  def unbox(packet,shared_secret,nonce)
  def unbox(<<mac::binary-size(16),c::binary>>,key,n) do
      <<pnonce::binary-size(32), m::binary>> =  Salsa20.crypt(thirtytwo_zeroes<>c,second_level_key(key,n),binary_part(n,16,8))
      case c |> Poly1305.hmac(pnonce) |> Poly1305.compare(mac) do
          true ->  m
          _    ->  :error
      end
  end

end
