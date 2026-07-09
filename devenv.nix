{ lib, pkgs, ... }:

{
  # https://devenv.sh/packages/
  packages = with pkgs; [
    golangci-lint
    xcaddy
  ];

  languages.go.enable = true;

  treefmt = {
    enable = true;
    config = {
      programs = {
        nixfmt.enable = true;
        goimports = {
          enable = true;
          priority = 1;
        };
        gofumpt = {
          enable = true;
          priority = 2;
        };
        yamlfmt.enable = true;
      };
      settings.formatter.gci = {
        command = lib.getExe pkgs.gci;
        options = [
          "write"
          "--skip-generated"
          "--skip-vendor"
          "--custom-order"
          "-s"
          "standard"
          "-s"
          "default"
          "-s"
          "prefix(github.com/caddyserver/caddy)"
        ];
        includes = [ "*.go" ];
        priority = 3;
      };
    };
  };

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    end-of-file-fixer.enable = true;
    check-json.enable = true;
    check-symlinks.enable = true;
    golangci-lint = {
      enable = true;
      package = pkgs.golangci-lint;
    };
    govulncheck = {
      enable = true;
      package = pkgs.govulncheck;
      entry = "${lib.getExe pkgs.govulncheck} ./...";
      # TODO: move back to pre-commit when nixpkgs ships Go 1.26.5.
      stages = [ "manual" ];
      pass_filenames = false;
      types = [ "go" ];
    };
    treefmt.enable = true;
    trim-trailing-whitespace.enable = true;
  };
}
