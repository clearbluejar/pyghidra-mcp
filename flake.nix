{
  description = "pyghidra-mcp packaged with Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
      };
      python = pkgs.python313;
      py = python.pkgs;

      ghidrecomp = py.buildPythonPackage rec {
        pname = "ghidrecomp";
        version = "0.5.9";
        pyproject = true;

        src = pkgs.fetchPypi {
          inherit pname version;
          hash = "sha256-ocluLUic2qMREO7kXWum8l3VZ/parj/WtQ9JgOood6I=";
        };

        build-system = with py; [
          setuptools
          wheel
        ];

        dependencies = with py; [
          pyghidra
          jpype1
          click
          lxml
          networkx
          pydot
          pyyaml
          requests
        ];
        doCheck = true;
        pythonImportsCheck = [
          "ghidrecomp"
        ];
      };

      pyghidra-mcp = py.buildPythonApplication {
        pname = "pyghidra-mcp";
        version = "0.2.2";

        src = ./.;

        pyproject = true;

        build-system = with py; [
          hatchling
        ];

        # python package dependencies
        dependencies = with py; [
          click
          click-option-group
          mcp 
          pyghidra    # needs ghidra >= 12.0
          chromadb
          ghidrecomp
        ]++ py.mcp.optional-dependencies.cli;
      };

      pyghidra-mcp-cli = py.buildPythonApplication {
        pname = "pyghidra-mcp-cli";
        version = "0.2.2";

        src = ./cli;
        pyproject = true;

        build-system = with py; [
          hatchling
        ];

        dependencies = with py; [
          click
          aiohttp
          pyghidra-mcp
        ];
      };
    in
    {
      # add both binary
      packages.${system} = {
        default = pkgs.symlinkJoin {
          name = "pyghidra-mcp-with-cli";

          paths = [
              pyghidra-mcp
              pyghidra-mcp-cli
            ];
        };
        inherit pyghidra-mcp pyghidra-mcp-cli;
      };
      # for nix run
      apps.${system} = {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/pyghidra-mcp";
        };

        pyghidra-mcp = {
          type = "app";
          program = "${self.packages.${system}.pyghidra-mcp}/bin/pyghidra-mcp";
        };

        pyghidra-mcp-cli = {
          type = "app";
          program = "${self.packages.${system}.pyghidra-mcp-cli}/bin/pyghidra-mcp-cli";
        };
      };
    };
}
