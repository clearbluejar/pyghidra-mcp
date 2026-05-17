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
      python = pkgs.python312;
      py = python.pkgs;
    in
    {
      packages.${system}.default = py.buildPythonApplication {
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
          pyghidra
          chromadb
          ghidrecomp
        ];
      };
    };
}