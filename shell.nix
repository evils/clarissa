{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [ libpcap perl zsh shellcheck glibc glibc.static ];
  shellHook = ''
    exec zsh
  '';
}
