{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ binutils perl asciidoctor ];
  buildInputs = with pkgs; [ libpcap glibc glibc.static ];
}
