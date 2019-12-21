{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ binutils perl asciidoctor shellcheck ];
  buildInputs = with pkgs; [ libpcap glibc glibc.static dnsutils ];
}
