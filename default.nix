with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "publicsuffix";
  buildInputs = [ gcc openssl gnumake cmake zlib ];
}
