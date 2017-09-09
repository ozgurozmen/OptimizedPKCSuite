#include <uECC_vli.h>
#include <uECC.h>
#include <types.h>


extern "C" {

static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of 
  // random noise). This can take a long time to generate random data if the result of analogRead(0) 
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }
      
      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

}  // extern "C"

void setup() {
  Serial.begin(115200);
  Serial.print("Testing BPV ECDSA\n");
  uECC_set_rng(&RNG);

  const struct uECC_Curve_t * curve = uECC_secp256r1();
  uint8_t privates[1024];
  uint8_t publics[2048];

  
  uint8_t private1[32];
  uint8_t k[32];
  
  uint8_t public1[64];
  uint8_t kPub[64];
  uint8_t sum[64];
  
  uint8_t secret1[32];
  uint8_t secret2[32];

  uint8_t hash[32] = {0};
  uint8_t sig[64] = {0};
  
  unsigned long a = micros();
  for (unsigned i = 0; i < 32; ++i) {
    uECC_make_key(public1, private1, curve);
    memcpy(publics + 64*i, public1, sizeof(public1));
    memcpy(privates + 32*i, private1, sizeof(private1));
  }
  unsigned long b = micros();
  unsigned long clockcycle;
  clockcycle = microsecondsToClockCycles(b-a);
  Serial.print("Made key 1 in "); Serial.println(clockcycle);
  a = micros();
 // uECC_make_key(public2, private2, curve);
  b = micros();
  clockcycle = microsecondsToClockCycles(b-a);
  Serial.print("Made key 2 in "); Serial.println(clockcycle);

  
  memcpy(hash, public1, sizeof(hash));

  a = micros();
//  if (!uECC_sign(private1, hash, sizeof(hash), sig, curve)) {
//     // printf("uECC_sign() failed\n");
//   }
  uint8_t add[64];
  uint8_t add2[64];

  uint8_t modAdd[32];
  uint8_t modAdd2[32];

  uECC_word_t kVLI[32];
  
  for (unsigned j = 0; j < 64; ++j) {
    add[j] = publics[j];
    add2[j] = publics[64 + j];
  }

  for (unsigned j = 0; j < 32; ++j) {
    modAdd[j] = privates[j];
    modAdd2[j] = privates[32 + j];
  }

  uECC_vli_bytesToNative(kVLI, modAdd , 32);
  EllipticAdd(add, add2, kPub, curve);
  modularAddULS(kVLI, modAdd2, kVLI,curve);

  for (unsigned i = 2; i < 32; ++i) {
    for (unsigned j = 0; j < 64; ++j) {
      add[j] = publics[(i*64) + j];
      add2[j] = kPub[j];
    }
    EllipticAdd(add, add2, kPub, curve);

    for (unsigned l = 0; l < 32; ++l) {
      modAdd2[l] = privates[32*i+l];
    }
    modularAddULS(kVLI, modAdd2, kVLI,curve);
  }

  uECC_vli_nativeToBytes(k, 32, kVLI);
  
//  Serial.print("kPUB = {");
//  for (unsigned i = 0; i < 64; ++i) { 
//     Serial.print("0x"); Serial.print(kPub[i], HEX); Serial.print(", ");
//  }
//  Serial.println("};");
//
//  uint8_t deneme[64];
//  uECC_compute_public_key(k, deneme, curve);
//  Serial.print("kPUBEquiv = {");
//  for (unsigned i = 0; i < 64; ++i) { 
//     Serial.print("0x"); Serial.print(deneme[i], HEX); Serial.print(", ");
//  }
//  Serial.println("};");

  uECC_vli_nativeToBytes(sig,32,kPub);
  modularInv(k, kVLI, curve);
  uECC_word_t d[32];
  uint8_t r2[32];
  uECC_word_t s[32];
  uECC_vli_nativeToBytes(r2, 32, kPub);
  uECC_vli_bytesToNative(d, private1, 32);

  uECC_vli_set(s, kPub, 32);
  modularMult(private1, r2, s, curve);

  modularAdd(s, hash, s , curve);
  
  uECC_vli_nativeToBytes(k, 32, kVLI);
  uECC_vli_nativeToBytes(r2, 32, s);

  modularMult(k,r2,s,curve);

  uECC_vli_nativeToBytes(sig + 32, 32, s);

  b = micros();
  clockcycle = microsecondsToClockCycles(b-a);
  Serial.print("Signing "); Serial.println(clockcycle);

  a = micros();
  if (!uECC_verify(public1, hash, sizeof(hash), sig, curve)) {
     // printf("uECC_verify() failed\n");
  } 
  b = micros();
  clockcycle = microsecondsToClockCycles(b-a);
  Serial.print("Verifying "); Serial.println(clockcycle);
}

void loop() {
 

  
  
}
