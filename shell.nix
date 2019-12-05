{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [ libpcap perl zsh shellcheck ];
  shellHook = ''
    exec zsh
  '';
}
