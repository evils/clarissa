{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ binutils perl zsh shellcheck ];
  buildInputs = with pkgs; [ libpcap glibc glibc.static ];
  shellHook = ''
    exec zsh
  '';
}
