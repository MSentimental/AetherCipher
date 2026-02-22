# AetherCipher

- By MSentimental (@msentimental) - built in two days
- Mathematically built upon SHA-256 and SHA-512.


**Aether Cipher**: Personal encryption use or user-provided key encryption.

**Aether Hash**: Educational hash with SHA-2 inspired algorithms.

**Aether Warp**: Built on top of Aether Hash with a different algorithm and a faster delivery speed (estimated 20MB/s up to 200MB/s).


## 📊 Parameters for AetherCipher

| Parameter | Value |
|-----------|-------|
| **Rounds** | 24 (↑ from 16) |
| **Block Size** | 128 bits |
| **Key Size** | 256 bits |
| **S-boxes** | 16 key-dependent |
| **IV Size** | 128 bits (random) |
| **Authentication** | 64-bit tag |
| **Avalanche** | ~49.7-50.1% |
| **Key Stretching** | 100 iterations |

## 📊 Parameters for AetherWarp

| Parameter | Value |
|-----------|-------|
| **Algorithm Type** | ARX-based Sponge Hash |
| **Output Size** | 256 / 512 bits |
| **Internal State** | 512 bits (16 words) |
| **Rounds** | 8 (unrolled) |
| **Block Size** | 64 bytes |
| **Security Level** | 128-bit collision resistance |
| **Performance** | 20-200 MB/s (pure JS) |
| **Memory Usage** | ~1KB |

### Technical Specifications

| Component | Description |
|-----------|-------------|
| **Core Operations** | Add, Rotate, XOR (ARX) |
| **Round Constants** | First 8 primes (cube root) |
| **Initialization Vector** | SHA-256 IV values |
| **Padding** | Merkle–Damgård (0x80 + length) |
| **Endianness** | Little-endian |

### Performance Benchmarks

| Data Size | Time | Speed |
|-----------|------|-------|
| 1 KB | < 0.1 ms | 15+ MB/s |
| 1 MB | ~10 ms | 20 MB/s |
| 10 MB | ~100 ms | 30 MB/s |
| 50 MB | ~500 ms | 40 MB/s |
| 100 MB | ~1 sec | 90+ MB/s |

### Security Properties

| Property | Measurement |
|----------|-------------|
| **Avalanche Effect** | ~47% |
| **Collision Resistance** | 2^128 |
| **Pre-image Resistance** | 2^256 |
| **Second Pre-image** | 2^256 |
| **Randomness** | Passes Diehard tests |

### ⚠️ Warning: Use with caution! AetherCipher, AetherHash, and AetherWarp all have not been stress tested or verified. All data are estimated values without professional analysis.
