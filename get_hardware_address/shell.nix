{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ asciidoctor zsh ];
  buildInputs = with pkgs; [ libpcap ];
  shellHook = ''
    exec zsh
  '';
}

