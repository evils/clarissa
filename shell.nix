{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [ libpcap ];
  shellHook = ''
    exec zsh
  '';
}
