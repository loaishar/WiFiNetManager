{pkgs}: {
  deps = [
    pkgs.libpcap
    pkgs.wireshark
    pkgs.tcpdump
    pkgs.sox
    pkgs.imagemagickBig
    pkgs.iana-etc
    pkgs.openssl
    pkgs.postgresql
  ];
}
