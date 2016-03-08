defmodule OAuth2.Strategy.JWT do
  @moduledoc """
  JSON Web Token (JWT) Profile

  https://tools.ietf.org/html/rfc7523
  """

  use OAuth2.Strategy

  import OAuth2.Util

  @doc """
  Not used for this strategy.
  """
  def authorize_url(_client, _params) do
    raise OAuth2.Error, reason: "This strategy does not implement `authorize_url`."
  end

  @doc """
  Retrieve an access token given the specified strategy.
  """
  def get_token(client, params, headers) do
    {token, params} = Keyword.pop(params, :token)

    unless token do
      raise OAuth2.Error, reason: "Missing required key `token` for `#{inspect __MODULE__}`"
    end

    jwt = generate_jwt(client, token)

    client
    |> put_param(:client_id, client.client_id)
    |> put_param(:client_secret, client.client_secret)
    |> put_param(:grant_type, "client_credentials")
    |> put_param(:client_assertion_type, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    |> put_param(:client_assertion, jwt)
    |> merge_params(params)
    |> put_headers(headers)
  end

  defp generate_jwt(client, token) do
    {alg, token} = Keyword.pop(token, :alg, "HS512")
    {secret, token} = Keyword.pop(token, :secret, client.client_secret)

    jwt = jwt(client, token)

    secret
    |> jwk
    |> JOSE.JWT.sign(jws(alg), jwt)
    |> JOSE.JWS.compact
    |> elem(1)
  end

  defp jwk(secret) do
    %{"kty" => "oct", "k" => :base64url.encode(secret)}
  end

  defp jws(alg) do
    %{"alg" => alg}
  end

  defp jwt(client, token) do
    %{"iss" => token[:iss] || client.client_id,
      "aud" => token[:aud],
      "sub" => token[:sub] || client.client_id,
      "exp" => token[:exp] || unix_now + 3600}
  end
end
