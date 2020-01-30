{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [ libpcap zsh ];
  shellHook = ''
    exec zsh
  '';
}

