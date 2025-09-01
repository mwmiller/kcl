defmodule Kcl.MixProject do
  use Mix.Project

  def project do
    [
      app: :kcl,
      version: "1.4.4",
      elixir: "~> 1.9",
      name: "KCl",
      source_url: "https://github.com/mwmiller/kcl",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  def application do
    []
  end

  defp deps do
    [
      {:ed25519, "~> 1.3"},
      {:curve25519, ">= 1.0.4"},
      {:salsa20, "~> 1.0"},
      {:poly1305, "~> 1.0"},
      {:ex_doc, "~> 0.23", only: :dev}
    ]
  end

  defp description do
    """
    A less savory pure Elixir NaCl (libsodium) crypto suite substitute
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "LICENSE*"],
      maintainers: ["Matt Miller"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/mwmiller/kcl",
        "Spec" => "http://cr.yp.to/highspeed/naclcrypto-20090310.pdf"
      }
    ]
  end
end
