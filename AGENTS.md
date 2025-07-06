для сборки запустить это:
git submodule update --init
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . --config Debug
дополнительно установить gbd и strace для отладки
