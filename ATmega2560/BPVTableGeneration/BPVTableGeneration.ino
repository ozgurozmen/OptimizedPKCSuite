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

  randomSeed(analogRead(0));

  const struct uECC_Curve_t * curve = uECC_secp192r1();
 // uint8_t privateCA[24];
  //uint8_t publicCA[48];
  
  uint8_t privateAlice1[24];
  uint8_t privateAlice2[24];

  //uint8_t privateBob1[24];
  uint8_t privateBob2[24];

  uint8_t publicAlice1[48];
  uint8_t publicAlice2[48];

  //uint8_t publicBob1[48];
  uint8_t publicBob2[48];

  uint8_t hash[24] = {0};
  uint8_t hash2[24] = {0};

  uint8_t pointAlice1[48];
  uint8_t pointBob1[48];

  uint8_t pointAlice2[48];
  uint8_t pointBob2[48];

  uint8_t deneme;

  long randNumber;
  uint8_t privateBob1[24] = {0xEB, 0xF9, 0x3D, 0xE3, 0x1B, 0xCC, 0x7D, 0x87, 0xE5, 0x16, 0x31, 0x73, 0xBB, 0x14, 0xA1, 0x2E, 0xBC, 0xE1, 0x36, 0xBA, 0xB, 0x3F, 0x47, 0xA1};
  uint8_t publicBob1[48] = {0x9D, 0x3F, 0x58, 0x94, 0x5F, 0x13, 0xFE, 0xEC, 0x99, 0x1A, 0xE3, 0xEC, 0x12, 0xE2, 0x20, 0xDD, 0x81, 0x96, 0x9C, 0x76, 0xC8, 0x5, 0xC, 0xCD, 0xE0, 0x36, 0x43, 0x2A, 0x3C, 0x2A, 0xA0, 0x0, 0x57, 0xAD, 0x1F, 0xC, 0x4D, 0x66, 0x26, 0x37, 0x38, 0xA0, 0xFD, 0x1A, 0x67, 0xD3, 0x48, 0xFD};

  uint8_t privateCA[24] = {0xB6, 0xE, 0x87, 0xB8, 0xDB, 0x7F, 0xB4, 0x3C, 0xBB, 0xDE, 0x1E, 0x1E, 0xCC, 0xFE, 0x44, 0x1, 0x26, 0xD4, 0xBB, 0xEE, 0xE8, 0x70, 0x18, 0x3E};
  uint8_t publicCA[48] = {0x9F, 0xD2, 0x62, 0xED, 0x71, 0x19, 0xEA, 0xF4, 0x64, 0x25, 0xCF, 0x22, 0x34, 0x7C, 0x90, 0xBA, 0xC6, 0x92, 0x24, 0x31, 0xBC, 0x9, 0x1E, 0x56, 0x55, 0x39, 0xC8, 0xAE, 0xBF, 0x7A, 0x79, 0x8B, 0xA3, 0xF2, 0xE5, 0x39, 0x5A, 0x48, 0xC9, 0x27, 0x48, 0x96, 0xEC, 0x4F, 0x68, 0x9C, 0xDB, 0xF9};


  unsigned long a,b,c,d;

//  for (unsigned i = 0; i < 24; i++)
//  {
//    randNumber = random(160);
//    Serial.print(randNumber); Serial.print(", ");
//  }
//  
//  
//  for (unsigned i = 0; i < 24; i++)
//  {
//    privateAlice1[i] = pgm_read_word_near(BPVTable + i);
//    //Serial.print("0x"); Serial.print(privateAlice1[i], HEX); Serial.print(", ");
//  }
//
//  for (unsigned i = 24; i < 72; i++)
//  {
//    publicAlice1[i-24] = pgm_read_word_near(BPVTable + i);
//    //Serial.print("0x"); Serial.print(publicAlice1[i], HEX); Serial.print(", ");
//  }
//
//  uECC_compute_public_key(privateAlice1, pointAlice1, curve);
//  
//  if (memcmp(publicAlice1, pointAlice1, 48) != 0) {
//    Serial.print("Shared secrets are not identical!\n");
//  } else {
//    Serial.print("Shared secrets are identical\n");
//  }
  sha256.reset();
  sha256.update(publicBob1, sizeof(publicBob1));
  sha256.finalize(hash2, sizeof(hash2));

  uECC_shared_secret2(publicBob1, hash2, pointAlice1, curve);
  EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);


  Serial.print("const PROGMEM  uint8_t BPVTable[] = {");
  for (unsigned i = 0; i < 160; ++i) {

    uECC_make_key(publicAlice1, privateAlice1, curve);
    for (unsigned j = 0; j < 24; ++j) {
      Serial.print("0x"); Serial.print(privateAlice1[j], HEX); Serial.print(", ");
    }
//    for (unsigned j = 0; j < 48; ++j) {
//      Serial.print("0x"); Serial.print(publicAlice1[j], HEX); Serial.print(", ");
//    }

    uECC_shared_secret2(pointAlice1, privateAlice1, pointBob1, curve);

    for (unsigned j = 0; j < 48; ++j) {
      Serial.print("0x"); Serial.print(pointBob1[j], HEX); Serial.print(", ");
    }
    
  }
  Serial.print("};");

//  uECC_make_key(publicBob1, privateBob1, curve);
//  Serial.print("uint8_t privateCA[24] = {");
//  for (unsigned j = 0; j < 24; ++j) {
//    Serial.print("0x"); Serial.print(privateBob1[j], HEX); Serial.print(", ");
//  }
//  Serial.print("};");
//  
//  Serial.print("uint8_t publicCA[48] = {");
//  for (unsigned j = 0; j < 48; ++j) {
//    Serial.print("0x"); Serial.print(publicBob1[j], HEX); Serial.print(", ");
//  }
//  Serial.print("};");

}

void loop() {
 
  


}
