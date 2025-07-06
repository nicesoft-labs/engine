для сборки запустить это
git submodule update --init
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
дополнительно устанавливая gbd и strace для отладки
