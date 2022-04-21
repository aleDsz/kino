defmodule Kino.SmartCell.Snowflake do
  @moduledoc false

  # A smart cell used to establish connection to a database.

  use Kino.JS, assets_path: "lib/assets/snowflake"
  use Kino.JS.Live
  use Kino.SmartCell, name: "Snowflake database connection"

  @impl true
  def init(attrs, ctx) do
    fields = %{
      "variable" => Kino.SmartCell.prefixed_var_name("conn", attrs["variable"]),
      "username" => attrs["username"] || "",
      "region" => attrs["region"] || "",
      "account" => attrs["account"] || "",
      "database" => attrs["database"] || "",
      "warehouse" => attrs["warehouse"] || "",
      "schema" => attrs["schema"] || "",
      "public_key_fingerprint" => attrs["public_key_fingerprint"] || "",
      "private_key" => attrs["private_key"] || ""
    }

    {:ok, assign(ctx, fields: fields, missing_dep: missing_dep())}
  end

  @impl true
  def handle_connect(ctx) do
    payload = %{
      fields: ctx.assigns.fields,
      missing_dep: ctx.assigns.missing_dep
    }

    {:ok, payload, ctx}
  end

  @impl true
  def handle_event("update_field", %{"field" => field, "value" => value}, ctx) do
    updated_fields = to_updates(ctx.assigns.fields, field, value)
    ctx = update(ctx, :fields, &Map.merge(&1, updated_fields))

    ctx =
      if missing_dep() == ctx.assigns.missing_dep do
        ctx
      else
        broadcast_event(ctx, "missing_dep", %{"dep" => missing_dep()})
        assign(ctx, missing_dep: missing_dep())
      end

    broadcast_event(ctx, "update", %{"fields" => updated_fields})

    {:noreply, ctx}
  end

  defp to_updates(fields, "variable", value) do
    if Kino.Utils.Code.valid_variable_name?(value) do
      %{"variable" => value}
    else
      %{"variable" => fields["variable"]}
    end
  end

  defp to_updates(_fields, field, value), do: %{field => value}

  @impl true
  def to_attrs(ctx) do
    ctx.assigns.fields
  end

  @impl true
  def to_source(attrs) do
    attrs
    |> to_quoted()
    |> Kino.Utils.Code.quoted_to_string()
  end

  defp to_quoted(attrs) do
    username = String.upcase(attrs["account"]) <> "." <> String.upcase(attrs["username"])

    quote do
      header = %{"alg" => "RS256", "typ" => "JWT"}
      unix_time = :os.system_time(:seconds)

      claims = %{
        "iss" => unquote(username <> "." <> attrs["public_key_fingerprint"]),
        "sub" => unquote(username),
        "exp" => unix_time + 3600,
        "iat" => unix_time
      }

      base_url = unquote("https://#{attrs["account"]}.#{attrs["region"]}.snowflakecomputing.com")

      connection_params = %{
        "database" => unquote(attrs["database"]),
        "warehouse" => unquote(attrs["warehouse"]),
        "schema" => unquote(attrs["schema"]),
        "role" => "SYSADMIN"
      }

      {_, token} =
        unquote(String.replace(attrs["private_key"], "\\n", "\n"))
        |> JOSE.JWK.from_pem()
        |> JOSE.JWT.sign(header, claims)
        |> JOSE.JWS.compact()

      unquote(quoted_var(attrs["variable"])) = Snowflake
      Kino.start_child({Finch, name: Snowflake})
    end
  end

  defp quoted_var(string), do: {String.to_atom(string), [], nil}

  defp missing_dep do
    unless ensure_loaded?() do
      """
      {:finch, "~> 0.11.0"},
        {:jason, "~> 1.3"},
        {:jose, "~> 1.11"}
      """
    end
  end

  defp ensure_loaded? do
    Code.ensure_loaded?(Finch) and
      Code.ensure_loaded?(JOSE) and
      Code.ensure_loaded?(Jason)
  end
end
