#include <uECC_vli.h>
#include <uECC.h>
#include <types.h>

#include <SHA256.h>
#include <string.h>
#include <avr/pgmspace.h>

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



SHA256 sha256;

void setup() {
  Serial.begin(115200);
  Serial.print("Testing Ephemeral ECHMQV\n");
  uECC_set_rng(&RNG);
}


void loop() {
  const struct uECC_Curve_t * curve = uECC_secp192r1();
  uint8_t privateCA[25];
  uint8_t private1[25];
  uint8_t private2[25];

  uint8_t publicCA[48];
  uint8_t public1[48];
  uint8_t public2[48];

  uint8_t hash[24] = {0};
  uint8_t hash2[24] = {0};
  uint8_t sig[48] = {0};
  uint8_t sig2[48] = {0};

  uint8_t key1[48];
  uint8_t key2[48];

  unsigned long a,b,c,d, clockcycle, clockcycle2;

  uint8_t privateEph1[25];
  uint8_t privateEph2[25];

  uint8_t publicEph1[48];
  uint8_t publicEph2[48];

  uint8_t hashD[24] = {0};
  uint8_t hashE[24] = {0};

  uECC_make_key(publicCA, privateCA, curve);

  uECC_make_key(public1, private1, curve);
  uECC_make_key(public2, private2, curve);

  sha256.reset();
  sha256.update(public1, sizeof(public1));
  sha256.finalize(hash, sizeof(hash));

  sha256.reset();
  sha256.update(public2, sizeof(public2));
  sha256.finalize(hash2, sizeof(hash2));

//  memcpy(hash, public1, sizeof(hash));
//  memcpy(hash2, public2, sizeof(hash2));

  if (!uECC_sign(privateCA, hash, sizeof(hash), sig, curve)) {
     Serial.print("uECC_sign() failed\n");
  }

  if (!uECC_sign(privateCA, hash2, sizeof(hash2), sig2, curve)) {
     Serial.print("uECC_sign() failed\n");
  }
  

  if (!uECC_verify(publicCA, hash, sizeof(hash), sig, curve)) {
     Serial.print("uECC_verify() failed\n");
  } 
  Serial.print("CA signature is verified\n");

  if (!uECC_verify(publicCA, hash2, sizeof(hash2), sig2, curve)) {
     printf("uECC_verify() failed\n");
  } 
  Serial.print("CA signature is verified\n");
  
//  int r = uECC_shared_secret(public2, private1, key1, curve);
//  if (!r) {
//    Serial.print("shared_secret() failed (1)\n");
//    return;
//  }
//  //printHex(key1,24);
//  
//  r = uECC_shared_secret(public1, private2, key2, curve);
//  if (!r) {
//    Serial.print("shared_secret() failed (1)\n");
//    return;
//  }


  a = micros();
  uECC_make_key(publicEph1, privateEph1, curve);

  sha256.reset();
  sha256.update(publicEph1, sizeof(publicEph1));
  sha256.finalize(hashD, sizeof(hashD));

  sha256.reset();
  sha256.update(publicEph2, sizeof(publicEph2));
  sha256.finalize(hashE, sizeof(hashE));
  b = micros();
  clockcycle = microsecondsToClockCycles(b-a);

  c = micros();
  uECC_make_key(publicEph2, privateEph2, curve);

  sha256.reset();
  sha256.update(publicEph1, sizeof(publicEph1));
  sha256.finalize(hashD, sizeof(hashD));

  sha256.reset();
  sha256.update(publicEph2, sizeof(publicEph2));
  sha256.finalize(hashE, sizeof(hashE));
 
  d = micros();
  clockcycle2 = microsecondsToClockCycles(d-c);


//  memcpy(hashD, publicEph1, sizeof(hashD));
//  memcpy(hashE, publicEph2, sizeof(hashE));

  a = micros();
  int r = uECC_shared_secret2(public2, hashE, key1, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }

  EllipticAdd(key1, publicEph2, key1, curve);

  modularMultAdd(hashD, private1, privateEph1, privateEph1, curve);
  r = uECC_shared_secret2(key1, privateEph1, key1, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }
  b = micros();
  clockcycle = clockcycle + microsecondsToClockCycles(b-a);
  Serial.print("Ephemeral ECHMQV: "); Serial.println(clockcycle);


  c = micros();
  r = uECC_shared_secret2(public1, hashD, key2, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }

  EllipticAdd(key2, publicEph1, key2, curve);
  modularMultAdd(hashE, private2, privateEph2, privateEph2, curve);
  
  r = uECC_shared_secret2(key2, privateEph2, key2, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }
  d = micros();
  clockcycle2 = clockcycle2 + microsecondsToClockCycles(d-c);
  Serial.print("Ephemeral ECHMQV: "); Serial.println(clockcycle2);

  if (memcmp(key1, key2, 24) != 0) {
    Serial.print("Shared secrets are not identical!\n");
  } else {
    Serial.print("Shared secrets are identical\n");
  }

}
