/*!
 * AetherCipher v1.0.1
 * 
 * [AetherCipher - Public]{@link https://cdn.jsdelivr.net/gh/msentimental/AetherCipher/build/aethercipher.min.js}
 *
 * @version 1.0.1
 * @author msentimental [lijinhan2025@gmail.com]
 * @copyright Strike Bot Inc. 2026
 * @license UNLICENSED - All Rights Reserved
 * [Unminified Version]
 */

class AetherCipher {
    constructor(key) {
        this.blockSize = 16;
        this.halfSize = 8;
        this.rounds = 16;
        this.masterKey = this._hashTo256(key);
        this._initKeySchedule();
    }

    _hashTo256(input) {
        const s = String(input);
        let h = new Uint32Array(8);
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;

        for (let i = 0; i < s.length; i++) {
            let c = s.charCodeAt(i);
            for (let j = 0; j < 8; j++) {
                h[j] ^= (c << (j*3)) | (c >>> (5 - j));
                h[j] = (h[j] * 0x9e3779b9) >>> 0;
                h[j] ^= h[(j+3)&7] ^ h[(j+7)&7];
            }
        }
        let out = new Uint8Array(32);
        for (let i = 0; i < 8; i++) {
            out[i*4]   = (h[i] >> 24) & 0xff;
            out[i*4+1] = (h[i] >> 16) & 0xff;
            out[i*4+2] = (h[i] >> 8) & 0xff;
            out[i*4+3] = h[i] & 0xff;
        }
        return out;
    }

    _entropyBoost(data) {
        let boosted = new Uint8Array(data.length);
    
        for (let i = 0; i < data.length; i++) {
            let a = data[i];
            let b = data[(i + 1) % data.length];
            let c = data[(i + 2) % data.length];
        
            boosted[i] = (a ^ b ^ c ^ i) & 0xff;
            boosted[i] ^= ((a << 1) | (b >> 7)) & 0xff;
            boosted[i] = (boosted[i] * 0x9E3779B9) >>> 24;
        }
    
        return boosted;
    }

    _initKeySchedule() {
        let rkBytes = new Uint8Array(this.rounds * this.halfSize);
        let seed = 0;
        for (let i = 0; i < 32; i++) seed ^= this.masterKey[i] << (i%4*8);
        const rand = this._chaoticRng(seed);

        for (let i = 0; i < rkBytes.length; i++) {
            rkBytes[i] = Math.floor(rand() * 256);
        }
        for (let i = 0; i < 32; i++) {
            rkBytes[i] ^= this.masterKey[i];
            rkBytes[rkBytes.length-1-i] ^= this.masterKey[i];
        }
        this.roundKeys = [];
        for (let r = 0; r < this.rounds; r++) {
            this.roundKeys.push(rkBytes.slice(r*this.halfSize, (r+1)*this.halfSize));
        }

        this.sboxes = [];
        for (let s = 0; s < 8; s++) {
            let box = new Uint8Array(256);
            for (let i = 0; i < 256; i++) {
                let v = i;
                v ^= this.masterKey[(s + i) % 32];
                v = ((v << 5) | (v >> 3)) & 0xff;
                v = (v + Math.floor(256 * (Math.sin(i*s) * 0.5 + 0.5))) & 0xff;
                box[i] = v;
            }
            this._makePermutation(box);
            this.sboxes.push(box);
        }
        this.invSboxes = [];
        for (let s = 0; s < 8; s++) {
            let inv = new Uint8Array(256);
            for (let i = 0; i < 256; i++) {
                inv[this.sboxes[s][i]] = i;
            }
            this.invSboxes.push(inv);
        }
    }

    _makePermutation(box) {
        let seen = new Array(256).fill(false);
        for (let i = 0; i < 256; i++) {
            while (seen[box[i]]) {
                box[i] = (box[i] + 1) & 0xff;
            }
            seen[box[i]] = true;
        }
    }

    _chaoticRng(seed) {
        return function() {
            seed = (seed * 1664525 + 1013904223) >>> 0;
            return (seed & 0xffffff) / 0x1000000;
        };
    }

    _F(half, round) {
        let out = new Uint8Array(half);
        for (let i = 0; i < 8; i++) out[i] ^= this.roundKeys[round][i];
        for (let i = 0; i < 8; i++) {
            let sboxIdx = (i + round) % 8;
            out[i] = this.sboxes[sboxIdx][out[i]];
        }
        let perm = new Uint8Array(8);
        for (let i = 0; i < 8; i++) {
            perm[i] = out[(i + round) % 8];
        }
        return perm;
    }

    encryptBlock(block) {
        let L = block.slice(0,8);
        let R = block.slice(8,16);
        for (let r=0; r<this.rounds; r++) {
            let newR = new Uint8Array(8);
            for (let i=0;i<8;i++) newR[i] = L[i] ^ this._F(R, r)[i];
            L = R;
            R = newR;
        }
        let out = new Uint8Array(16);
        out.set(L,0);
        out.set(R,8);
        return out;
    }

    decryptBlock(block) {
        let L = block.slice(0,8);
        let R = block.slice(8,16);
        for (let r=this.rounds-1; r>=0; r--) {
            let newL = new Uint8Array(8);
            for (let i=0;i<8;i++) newL[i] = R[i] ^ this._F(L, r)[i];
            R = L;
            L = newL;
        }
        let out = new Uint8Array(16);
        out.set(L,0);
        out.set(R,8);
        return out;
    }

    _pad(data) {
        let padLen = this.blockSize - (data.length % this.blockSize);
        let padded = new Uint8Array(data.length + padLen);
        padded.set(data);
        for (let i = data.length; i < padded.length; i++) padded[i] = padLen;
        return padded;
    }

    _unpad(data) {
        let padLen = data[data.length-1];
        if (padLen < 1 || padLen > this.blockSize) throw new Error('Invalid padding');
        return data.slice(0, data.length - padLen);
    }

    _entropyFinalizer(data, round) {
        let result = new Uint8Array(data.length);
 
        for (let i = 0; i < data.length; i++) {
            let a = data[i];
            let b = data[(i + 5) % data.length];

            result[i] = a ^ (b << 1) ^ (b >> 1) ^ (round & 0xff) ^ (i * 0x17);
        }
    
        return result;
    }

    _reversibleMix(data, round = 0) {
        let mixed = new Uint8Array(data.length);
    
        for (let i = 0; i < data.length; i++) {
            mixed[i] = data[i] ^ ((i + round) & 0xff);
        }
    
        return mixed;
    }

    encrypt(plaintext, ivHex = null) {
        let plainBytes = new TextEncoder().encode(plaintext);
        let padded = this._pad(plainBytes);

        let iv;
        if (ivHex && ivHex.length === 32) {
            iv = new Uint8Array(16);
            for (let i=0; i<16; i++) iv[i] = parseInt(ivHex.substr(i*2,2),16);
        } else {
            iv = crypto.getRandomValues(new Uint8Array(16));
        }

        let cipherBlocks = [];
        let prev = iv;

        for (let i=0; i<padded.length; i+=16) {
            let block = padded.slice(i, i+16);
            for (let j=0; j<16; j++) block[j] ^= prev[j];
            let enc = this.encryptBlock(block);


            cipherBlocks.push(enc);
            prev = enc;
        }
        let result = new Uint8Array(iv.length + padded.length);
        result.set(iv);
        let pos = iv.length;
        for (let i = 0; i < cipherBlocks.length; i++) {
            // let mixed = this._reversibleMix(cipherBlocks[i], i);
            // result.set(mixed, pos);
            let finalized = this._entropyFinalizer(cipherBlocks[i], i);
            result.set(finalized, pos);
            pos += 16;
        }
        return this._bytesToHex(result);
    }

    decrypt(cipherHex) {
        let data = this._hexToBytes(cipherHex);
        if (data.length < 16) throw new Error('Ciphertext too short');
    
        let iv = data.slice(0, 16);
        let finalizedBlocks = [];
        for (let i = 16; i < data.length; i += 16) {
            finalizedBlocks.push(data.slice(i, i + 16));
        }
    
        let cipherBlocks = [];
        for (let i = 0; i < finalizedBlocks.length; i++) {
            let finalized = finalizedBlocks[i];
            let reversed = new Uint8Array(16);
        
            for (let j = 0; j < 16; j++) {
                let a = finalized[j];
                let b = finalized[(j + 5) % 16];
                reversed[j] = a ^ (b << 1) ^ (b >> 1) ^ (i & 0xff) ^ (j * 0x17);
            }
            cipherBlocks.push(reversed);
        }
    
        let plainBlocks = [];
        let prev = iv;
    
        for (let block of cipherBlocks) {
            let dec = this.decryptBlock(block);
            for (let j = 0; j < 16; j++) dec[j] ^= prev[j];
            plainBlocks.push(dec);
            prev = block;
        }
    
        let plainPadded = new Uint8Array(plainBlocks.length * 16);
        let pos = 0;
        for (let b of plainBlocks) { 
            plainPadded.set(b, pos); 
            pos += 16; 
        }
    
        let plainBytes = this._unpad(plainPadded);
        return new TextDecoder().decode(plainBytes);
    }

    _bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
    }

    _hexToBytes(hex) {
        let bytes = new Uint8Array(hex.length/2);
        for (let i=0; i<hex.length; i+=2) bytes[i/2] = parseInt(hex.substr(i,2),16);
        return bytes;
    }

    testVectors() {
        const vectors = [
            { key: 'key1', plain: 'Hello World!', iv: '1' },
            { key: '🌟🔥', plain: 'Creative unicode ✓', iv: '1' },
            { key: 'longkey'.repeat(10), plain: 'A'.repeat(300), iv: '1' }
        ];
        let results = [];
        for (let v of vectors) {
            let cipher = new AetherCipher(v.key);
            let enc = cipher.encrypt(v.plain, v.iv);
            let dec = cipher.decrypt(enc);
            let pass = (dec === v.plain);
            results.push({ key: v.key.substring(0,10)+'…', plain: v.plain.substring(0,20)+'…', pass });
        }
        return results;
    }

    avalancheTest() {
        let cipher = new AetherCipher('avalanche-key');
        let plain1 = 'Hello World! This is a test.';
        let plain2 = 'Hello World! This is a test?';
        let enc1 = cipher.encrypt(plain1, '1');
        let enc2 = cipher.encrypt(plain2, '1');
        let b1 = this._hexToBytes(enc1);
        let b2 = this._hexToBytes(enc2);
        let diff = 0, total = b1.length * 8;
        for (let i=0; i<b1.length; i++) {
            let x = b1[i] ^ b2[i];
            while (x) { diff += x & 1; x >>= 1; }
        }
        return (diff / total * 100).toFixed(1);
    }
}
