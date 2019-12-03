{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [ libpcap perl zsh ];
  shellHook = ''
    exec zsh
  '';
}
