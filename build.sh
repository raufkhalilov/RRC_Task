sudo rm -r src/*
sudo rm -r build/*
sudo mkdir src
sudo mkdir build
sudo rm server
sudo rm client


asn1c RRCConnectionRequest.asn1 -D src -pdu=auto -fcompound-names -no-gen-OER -no-gen-example -fno-include-deps
gcc -g -Isrc client.c src/*.c -o build/client  -lsctp -DPDU=auto -DASN_DISABLE_OER_SUPPORT
gcc -g -Isrc server.c src/*.c -o build/server  -lsctp -DPDU=auto -DASN_DISABLE_OER_SUPPORT
