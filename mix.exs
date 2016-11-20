defmodule Kcl.Mixfile do
  use Mix.Project

  def project do
    [app: :kcl,
     version: "0.6.5",
     elixir: "~> 1.3",
     name: "KCl",
     source_url: "https://github.com/mwmiller/kcl",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description,
     package: package,
     deps: deps]
  end

  def application do
    []
  end

  defp deps do
    [
      {:ed25519, "~> 0.2"},
      {:curve25519, "~> 0.1"},
      {:salsa20, "~> 0.3"},
      {:poly1305, "~> 0.4"},
      {:earmark, "~> 1.0", only: :dev},
      {:ex_doc, "~> 0.14", only: :dev},
    ]
  end

  defp description do
    """
    KCl - a less savory pure Elixir NaCl crypto suite substitute
    """
  end

  defp package do
    [
     files: ["lib", "mix.exs", "README*", "LICENSE*", ],
     maintainers: ["Matt Miller"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/mwmiller/kcl",
              "Spec"   => "http://cr.yp.to/highspeed/naclcrypto-20090310.pdf",
             }
    ]
  end

end
