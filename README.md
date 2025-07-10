# XSalsa20 Library

A C implementation of the XSalsa20 cipher.

## Building

### Requires

- CMake 3.16 or later
- C compiler with C17 support (GCC, Clang, MSVC)

```bash
git clone <repository-url>
cd XSalsa20

mkdir build && cd build
cmake ..
make
make test
```

Optionally - install:

```bash
# Install (optional)
sudo make install
```

### Build Options

You can customize the build with the following CMake options:

- `BUILD_TESTS=ON/OFF` - Build test executables (default: ON)
- `BUILD_BENCHMARKS=ON/OFF` - Build benchmark executables (default: ON)
- `BUILD_SHARED=ON/OFF` - Build shared library (default: OFF)
- `BUILD_STATIC=ON/OFF` - Build static library (default: ON)
- `CMAKE_BUILD_TYPE` - Build type (Debug, Release, RelWithDebInfo, MinSizeRel)

Example:

```bash
cmake -DBUILD_SHARED=ON -DBUILD_STATIC=OFF ..
```

## Usage

### Basic Usage

```c
#include "xsalsa.h"
#include <string.h>

int main() {
    unsigned char key[32] = { /* your 32-byte key */ };
    unsigned char nonce[24] = { /* your 24-byte nonce */ };
    const char *plaintext = "Hello, World!";
    unsigned long plaintext_len = strlen(plaintext);
    
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    
    // One-shot encryption
    if (xsalsa20_memory(key, 32, nonce, 24, 20, 
                        (const unsigned char*)plaintext, plaintext_len, encrypted) == XSALSA_OK) {
        printf("Encryption successful\n");
    }
    
    // One-shot decryption (same operation)
    if (xsalsa20_memory(key, 32, nonce, 24, 20, 
                        encrypted, plaintext_len, decrypted) == XSALSA_OK) {
        printf("Decryption successful\n");
    }
    
    return 0;
}
```

### Streaming Interface

```c
#include "xsalsa.h"

int main() {
    xsalsa20_state st;
    unsigned char key[32] = { /* your 32-byte key */ };
    unsigned char nonce[24] = { /* your 24-byte nonce */ };
    
    // Initialize the cipher
    if (xsalsa20_setup(&st, key, 32, nonce, 24, 20) == XSALSA_OK) {
        // Process data in chunks
        unsigned char chunk[1024];
        unsigned char encrypted_chunk[1024];
        
        // Encrypt chunk
        xsalsa20_crypt(&st, chunk, sizeof(chunk), encrypted_chunk);
        
        // Clean up
        xsalsa20_done(&st);
    }
    
    return 0;
}
```

### Linking with Your Project

#### Using CMake

```cmake
# Find the library
find_package(XSalsa20 REQUIRED)

# Link with your target
target_link_libraries(your_target XSalsa20::xsalsa20_static)
```

#### Using pkg-config

```bash
# Compile
gcc -c your_file.c $(pkg-config --cflags xsalsa20)

# Link
gcc your_file.o -o your_program $(pkg-config --libs xsalsa20)
```

#### Manual Linking

```bash
# Static library
gcc your_file.c -I/usr/local/include/xsalsa20 -L/usr/local/lib -lxsalsa20 -o your_program

# Shared library
gcc your_file.c -I/usr/local/include/xsalsa20 -L/usr/local/lib -lxsalsa20 -o your_program
```

## Short Reference

### Functions

- `xsalsa20_setup()` - Initialize XSalsa20 context
- `xsalsa20_crypt()` - Encrypt/decrypt data
- `xsalsa20_keystream()` - Generate keystream bytes
- `xsalsa20_done()` - Clean up XSalsa20 state
- `xsalsa20_memory()` - One-shot encryption/decryption
- `xsalsa20_test()` - Run self-test

### Error Codes

- `XSALSA_OK` - Operation successful
- `XSALSA_ERROR` - General error
- `XSALSA_INVALID_ARG` - Invalid argument
- `XSALSA_INVALID_KEYSIZE` - Invalid key size (must be 32 bytes)
- `XSALSA_INVALID_NONCE_SIZE` - Invalid nonce size (must be 24 bytes)
- `XSALSA_INVALID_ROUNDS` - Invalid number of rounds
- `XSALSA_OVERFLOW` - Buffer overflow

## Testing & Benchmarking

```bash
cd build
make test
```

```bash
cd build
./bin/bench_xsalsa
```

## Installation

The library can be installed system-wide:

```bash
cd build
sudo make install
```

This installs:

- Headers to `/usr/local/include/xsalsa20/`
- Libraries to `/usr/local/lib/`
- Executables to `/usr/local/bin/`
- CMake config files to `/usr/local/lib/cmake/XSalsa20/`
- pkg-config file to `/usr/local/lib/pkgconfig/`
