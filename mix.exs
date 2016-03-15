defmodule Kcl.Mixfile do
  use Mix.Project

  def project do
    [app: :kcl,
     version: "0.1.1",
     elixir: "~> 1.2",
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
      {:curve25519, "~> 0.1"},
      {:salsa20, "~> 0.3"},
      {:poly1305, "~> 0.4"},
      {:power_assert, "~> 0.0.8", only: :test},
      {:earmark, ">= 0.0.0", only: :dev},
      {:ex_doc, "~> 0.11.4", only: :dev},
    ]
  end

  defp description do
    """
    KCl - a poor NaCL crypto suite substitute
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
