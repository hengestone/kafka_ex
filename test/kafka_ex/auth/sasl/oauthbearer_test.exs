defmodule KafkaEx.Auth.SASL.OAuthBearerTest do
  use ExUnit.Case, async: true

  alias KafkaEx.Auth.SASL.OAuthBearer
  alias KafkaEx.Auth.Config

  describe "mechanism_name/1" do
    test "returns OAUTHBEARER" do
      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{token_provider: fn -> {:ok, "token"} end}
        })

      assert OAuthBearer.mechanism_name(config) == "OAUTHBEARER"
    end
  end

  describe "authenticate/2" do
    test "returns error when token_provider returns error" do
      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{token_provider: fn -> {:error, :token_expired} end}
        })

      send_fun = fn _msg -> {:ok, nil} end

      assert {:error, :token_expired} = OAuthBearer.authenticate(config, send_fun)
    end

    test "returns error for invalid token (empty string)" do
      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{token_provider: fn -> {:ok, ""} end}
        })

      send_fun = fn _msg -> {:ok, nil} end

      assert {:error, :invalid_token} = OAuthBearer.authenticate(config, send_fun)
    end

    test "sends token in RFC 7628 format" do
      token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"

      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{token_provider: fn -> {:ok, token} end}
        })

      send_fun = fn msg ->
        send(self(), {:auth_message, msg})
        {:ok, nil}
      end

      assert :ok = OAuthBearer.authenticate(config, send_fun)

      assert_receive {:auth_message, message}
      assert String.starts_with?(message, "n,,\x01auth=Bearer ")
      assert String.contains?(message, token)
      assert String.ends_with?(message, "\x01\x01")
    end

    test "includes extensions in message when provided" do
      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{
            token_provider: fn -> {:ok, "test-token"} end,
            extensions: %{"traceId" => "abc123", "tenantId" => "tenant1"}
          }
        })

      send_fun = fn msg ->
        send(self(), {:auth_message, msg})
        {:ok, nil}
      end

      assert :ok = OAuthBearer.authenticate(config, send_fun)

      assert_receive {:auth_message, message}
      assert String.contains?(message, "\x01traceId=abc123")
      assert String.contains?(message, "\x01tenantId=tenant1")
    end

    test "succeeds when the broker answers with an empty server message" do
      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{token_provider: fn -> {:ok, "test-token"} end}
        })

      send_fun = fn msg ->
        send(self(), {:auth_message, msg})
        {:ok, ""}
      end

      assert :ok = OAuthBearer.authenticate(config, send_fun)
      assert_receive {:auth_message, _initial_response}
      refute_receive {:auth_message, _}
    end

    test "acknowledges an RFC 7628 error challenge and returns token_rejected" do
      challenge = ~s({"status":"invalid_token"})

      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{token_provider: fn -> {:ok, "test-token"} end}
        })

      send_fun = fn msg ->
        send(self(), {:auth_message, msg})

        case msg do
          <<0x01>> -> {:error, {:auth_failed, :sasl_authentication_failed}}
          _initial_response -> {:ok, challenge}
        end
      end

      assert {:error, {:auth_failed, :token_rejected, ^challenge}} =
               OAuthBearer.authenticate(config, send_fun)

      assert_receive {:auth_message, "n,,\x01auth=Bearer test-token\x01\x01"}
      assert_receive {:auth_message, <<0x01>>}
    end

    test "returns token_rejected when the broker accepts the error challenge acknowledgement" do
      challenge = ~s({"status":"invalid_token"})

      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{token_provider: fn -> {:ok, "test-token"} end}
        })

      send_fun = fn
        <<0x01>> -> {:ok, nil}
        _initial_response -> {:ok, challenge}
      end

      assert {:error, {:auth_failed, :token_rejected, ^challenge}} =
               OAuthBearer.authenticate(config, send_fun)
    end

    test "returns error when send_fun fails" do
      config =
        Config.new(%{
          mechanism: :oauthbearer,
          mechanism_opts: %{token_provider: fn -> {:ok, "test-token"} end}
        })

      send_fun = fn _msg -> {:error, :connection_closed} end

      assert {:error, :connection_closed} = OAuthBearer.authenticate(config, send_fun)
    end
  end
end
