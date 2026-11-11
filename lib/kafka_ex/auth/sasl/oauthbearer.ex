defmodule KafkaEx.Auth.SASL.OAuthBearer do
  @moduledoc """
  SASL/OAUTHBEARER mechanism for Kafka (KIP-255, KIP-342).

  ## Configuration

      KafkaEx.Auth.Config.new(%{
        mechanism: :oauthbearer,
        mechanism_opts: %{
          token_provider: fn -> {:ok, "jwt-token"} end,
          extensions: %{"traceId" => "abc123"}  # optional, KIP-342
        }
      })

  ## Token Provider

  The `token_provider` is a 0-arity function returning:
  - `{:ok, token}` - JWT token string
  - `{:error, reason}` - failure

  The provider is called on each new connection and is responsible for
  caching and refreshing tokens.

  ## Rejected Tokens

  A broker that rejects the token answers with an RFC 7628 error challenge, a
  JSON message such as `{"status":"invalid_token"}`, in a response without an
  error code. The client acknowledges it with `%x01` and the broker then fails
  the exchange. `authenticate/2` returns
  `{:error, {:auth_failed, :token_rejected, challenge}}` in that case, so the
  caller can drop the token and fetch a new one.
  """

  @behaviour KafkaEx.Auth.Mechanism

  alias KafkaEx.Auth.Config

  @kvsep <<0x01>>

  @impl true
  def mechanism_name(_config), do: "OAUTHBEARER"

  @impl true
  def authenticate(%Config{mechanism_opts: opts}, send_fun) do
    with {:ok, token} <- fetch_token(opts) do
      case send_fun.(build_initial_response(token, opts)) do
        {:ok, challenge} when challenge in [nil, ""] -> :ok
        {:ok, challenge} -> reject_error_challenge(send_fun, challenge)
        {:error, _} = err -> err
      end
    end
  end

  # RFC 7628 3.2.2: the broker fails the exchange after the %x01 acknowledgement, so its reply
  # carries no more information than the challenge.
  defp reject_error_challenge(send_fun, challenge) do
    _ = send_fun.(@kvsep)
    {:error, {:auth_failed, :token_rejected, challenge}}
  end

  defp fetch_token(%{token_provider: provider}) when is_function(provider, 0) do
    case provider.() do
      {:ok, token} when is_binary(token) and byte_size(token) > 0 -> {:ok, token}
      {:ok, _} -> {:error, :invalid_token}
      {:error, _} = err -> err
    end
  end

  defp fetch_token(_), do: {:error, :missing_token_provider}

  # RFC 7628 / KIP-255: "n,,\x01auth=Bearer <token>[\x01ext=val...]\x01\x01"
  defp build_initial_response(token, opts) do
    extensions = Map.get(opts, :extensions, %{})
    "n,,\x01auth=Bearer #{token}#{encode_extensions(extensions)}\x01\x01"
  end

  defp encode_extensions(exts) when map_size(exts) == 0, do: ""

  defp encode_extensions(exts) do
    Enum.map_join(exts, "", fn {k, v} -> "\x01#{k}=#{v}" end)
  end
end
