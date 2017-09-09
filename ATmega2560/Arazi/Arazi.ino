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
  Serial.print("Testing Arazi\n");
  uECC_set_rng(&RNG);
}


void loop() {
  const struct uECC_Curve_t * curve = uECC_secp192r1();
  uint8_t privateCA[24];
  uint8_t publicCA[48];
  
  uint8_t privateAlice1[24];
  uint8_t privateAlice2[24];

  uint8_t privateBob1[24];
  uint8_t privateBob2[24];

  uint8_t publicAlice1[48];
  uint8_t publicAlice2[48];

  uint8_t publicBob1[48];
  uint8_t publicBob2[48];

  uint8_t hash[24] = {0};
  uint8_t hash2[24] = {0};

  uint8_t pointAlice1[48];
  uint8_t pointBob1[48];

  uint8_t pointAlice2[48];
  uint8_t pointBob2[48];

  unsigned long a,b,c,d;

  uECC_make_key(publicCA, privateCA, curve);
  uECC_make_key(publicAlice1, privateAlice1, curve);
  uECC_make_key(publicBob1, privateBob1, curve);
  
  a = micros();
  sha256.reset();
  sha256.update(publicAlice1, sizeof(publicAlice1));
  sha256.finalize(hash, sizeof(hash));
  b = micros();
  unsigned long clockcycle;
  clockcycle = microsecondsToClockCycles(b-a);
    
  c = micros();
  sha256.reset();
  sha256.update(publicBob1, sizeof(publicBob1));
  sha256.finalize(hash2, sizeof(hash2));
  d = micros();
  unsigned long clockcycle2;
  clockcycle2 = microsecondsToClockCycles(d-c);

  
//  memcpy(hash, publicAlice1, sizeof(hash));
//  memcpy(hash2, publicBob1, sizeof(hash2));

  modularMultAdd(hash, privateAlice1, privateCA, privateAlice1, curve);
  modularMultAdd(hash2, privateBob1, privateCA, privateBob1, curve);


 // modularAdd2(privateAlice1, privateCA, privateAlice1, curve);
  //modularAdd2(privateBob1, privateCA, privateBob1, curve);

//  modularMult2(privateAlice1, hash, privateAlice1, curve);
//  modularMult2(privateBob1, hash2, privateBob1, curve);


  a = micros();
  uECC_make_key(publicAlice2, privateAlice2, curve);
  b = micros();
  clockcycle = clockcycle + microsecondsToClockCycles(b-a);
//  Serial.print("Made key 1 in "); Serial.println(clockcycle);

  c = micros();
  uECC_make_key(publicBob2, privateBob2, curve);
  d = micros();
  clockcycle2 = clockcycle2 + microsecondsToClockCycles(d-c);
//  Serial.print("Made key 2 in "); Serial.println(clockcycle2);

  
  a = micros();
  int r = uECC_shared_secret2(publicBob2, privateAlice2, pointAlice2, curve);
  b = micros();
  clockcycle = clockcycle + microsecondsToClockCycles(b-a);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }
  
  c = micros();
  r = uECC_shared_secret2(publicAlice2, privateBob2, pointBob2, curve);
  d = micros();
  clockcycle2 = clockcycle2 + microsecondsToClockCycles(d-c);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }
  
  

  r = uECC_shared_secret2(publicBob1, hash2, pointAlice1, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }
  EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);
  r = uECC_shared_secret2(pointAlice1, privateAlice1, pointAlice1, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }
  
  r = uECC_shared_secret2(publicAlice1, hash, pointBob1, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }
  EllipticAdd(pointBob1, publicCA, pointBob1, curve);
  r = uECC_shared_secret2(pointBob1, privateBob1, pointBob1, curve);

  a = micros();
  EllipticAdd(pointAlice1, pointAlice2, pointAlice1, curve);
  b = micros();
  clockcycle = clockcycle + microsecondsToClockCycles(b-a);
  Serial.print("Arazi in: "); Serial.println(clockcycle);


  c = micros();
  EllipticAdd(pointBob1, pointBob2, pointBob1, curve);
  d = micros();
  clockcycle2 = clockcycle2 + microsecondsToClockCycles(d-c);
  Serial.print("Arazi in: "); Serial.println(clockcycle2);

  if (memcmp(pointAlice1, pointBob1, 24) != 0) {
    Serial.print("Shared secrets are not identical!\n");
  } else {
    Serial.print("Shared secrets are identical\n");
  }

}
