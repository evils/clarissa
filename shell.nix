{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ binutils perl zsh shellcheck asciidoctor ];
  buildInputs = with pkgs; [ libpcap glibc glibc.static ];
  shellHook = ''
    exec zsh
  '';
}
