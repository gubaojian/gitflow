cd third_party/uWebSockets
cd uSockets
cd boringssl
mkdir -p build
cmake -B build --skip_tests -DCMAKE_BUILD_TYPE=Release
make -C build
cd ..
## with boringssl
make WITH_BORINGSSL=1
## make uWebSockets WITH_ZLIB=0
cd ..
make WITH_BORINGSSL=1 
cd ..
cd libuuid-1.0.3
./configure
make
cd ..
cd zlib-1.2.12
./configure
make -j2
cd ..