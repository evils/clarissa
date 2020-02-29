{ stdenv, fetchFromGitLab, libpcap, perl, asciidoctor

}:

stdenv.mkDerivation rec {

  pname = "clarissa";
  version = "v1.0";

  src = fetchFromGitLab {
    owner = "evils";
    repo = "clarissa";
    rev = version;
    sha256 = "0000000000000000000000000000000000000000000000000000";
  };

  nativeBuildInputs = [ perl asciidoctor ];
  buildInputs = [ libpcap ];

  doCheck = true;

  makeFlags = [ "DESTDIR=${placeholder "out"}" "PREFIX=" "SYSDINST=false" ];

  meta = with stdenv.lib; {
    description = "Near-real-time network census daemon";
    longDescription = ''
      Clarissa is a daemon which keeps track of connected MAC addresses on a network.
      It can report these with sub-second resolution and can monitor passively.
    '';
    homepage = "https://gitlab.com/evils/clarissa";
    license = licenses.bsd3;
    platforms = platforms.linux;
    maintainers = [ maintainers.evils ];
  };
}
