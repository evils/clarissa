{ lib, stdenv
, fetchFromGitLab
, libpcap, perl
, asciidoctor
}:

stdenv.mkDerivation rec {

  pname = "clarissa";
  version = "1.0-61-g8313b04";

  src = fetchFromGitLab {
    owner = "evils";
    repo = "clarissa";
    rev = "8313b04119e21615f276c47e5af8e5b9803a9df5";
    sha256 = "1fp7alfh59f069051wscqdih7mfi1bmdnsqr1jpcca79h1qwamc9";
  };

  nativeBuildInputs = [ asciidoctor ];
  buildInputs = [ libpcap ];

  outputs = [ "out" "man" ];

  makeFlags = [ "DESTDIR=${placeholder "out"}" "PREFIX=" ];

  dontBuild = true;
  installTargets = [ "install-clarissa" ];

  doCheck = true;
  checkTarget = "test";
  checkInputs = [ perl ];

  meta = with lib; {
    description = "Near-real-time network census daemon";
    longDescription = ''
      Clarissa is a daemon which keeps track of connected MAC addresses on a network.
      It can report these with sub-second resolution and can monitor passively.
    '';
    homepage = "https://gitlab.com/evils/clarissa";
    license = licenses.bsd3;
    platforms = platforms.unix;
    maintainers = [ maintainers.evils ];
  };
}
