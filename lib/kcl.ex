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
  defp second_level_key(k,n) when byte_size(n) == 24, do: k |> first_level_key |> Salsa20.hash(binary_part(n,0,16))

  defp sixteen_zeroes,   do: <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>
  defp thirtytwo_zeroes, do: sixteen_zeroes<>sixteen_zeroes

  @doc """
  box up an authenticated packet
  """
  @spec box(binary, key, key, nonce) :: binary
  def box(msg,our_private,their_public,n) do
      key = Curve25519.derive_shared_secret(our_private,their_public) |> second_level_key(n)
      <<pnonce::binary-size(32), c::binary>> =  Salsa20.crypt(thirtytwo_zeroes<>msg,key,binary_part(n,16,8))
      Poly1305.hmac(c,pnonce)<>c
  end

  @doc """
  unbox an authenticated packet

  Returns `:error` when the packet contents cannot be authenticated, otherwise
  the decrypted payload.
  """
  @spec unbox(binary, key, key, nonce) :: binary | :error
  def unbox(packet,our_private,their_public,n)
  def unbox(<<mac::binary-size(16),c::binary>>,o,t,n) do
      key = Curve25519.derive_shared_secret(o,t) |> second_level_key(n)
      <<pnonce::binary-size(32), m::binary>> =  Salsa20.crypt(thirtytwo_zeroes<>c,key,binary_part(n,16,8))
      case c |> Poly1305.hmac(pnonce) |> Poly1305.compare(mac) do
          true ->  m
          _    ->  :error
      end
  end

end
