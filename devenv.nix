{ pkgs, ... }:

{
  # https://devenv.sh/packages/
  packages = with pkgs; [
    pre-commit
  ];

  languages.go.enable = true;

  # https://devenv.sh/git-hooks/
  # git-hooks.hooks.shellcheck.enable = true;

}
