#include <uECC_vli.h>
#include <uECC.h>
#include <types.h>

#include <SHA256.h>
#include <AES.h>
#include <CTR.h>
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


CTR<AES128> ctraes128;
SHA256 sha256;

void setup() {
  Serial.begin(115200);
  Serial.print("Testing ECIES\n");
  uECC_set_rng(&RNG);
}


void loop() {
  const struct uECC_Curve_t * curve = uECC_secp192r1();
  
  uint8_t privateAlice1[24];

  uint8_t privateBob1[24];

  uint8_t publicAlice1[48];

  uint8_t publicBob1[48];

  uint8_t hash[32] = {0};
  uint8_t hash2[32] = {0};

  uint8_t keyAliceEnc[16] = {0};
  uint8_t keyAliceMac[16] = {0};
  uint8_t ivAlice[16] = {0};
  uint8_t keyBobEnc[16] = {0};
  uint8_t keyBobMac[16] = {0};
  uint8_t ivBob[16] = {0};

  uint8_t message[32] = {0};
  uint8_t messageBob[32] = {0};

  uint8_t ciphertext[32];

  uint8_t tag[16] = {0};
  uint8_t tagBob[16] = {0};

  uint8_t pointAlice1[48];
  uint8_t pointBob1[48];


  unsigned long a,b,c,d;

  uECC_make_key(publicBob1, privateBob1, curve);

  a = micros();
  uECC_make_key(publicAlice1, privateAlice1, curve);
  int r = uECC_shared_secret2(publicBob1, privateAlice1, pointAlice1, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }

  sha256.reset();
  sha256.update(pointAlice1, sizeof(pointAlice1));
  sha256.finalize(hash, sizeof(hash));
  
  memcpy(keyAliceEnc, hash, sizeof(keyAliceEnc));
  memcpy(keyAliceMac, hash + 16, sizeof(keyAliceMac));

  ctraes128.setKey(keyAliceEnc, ctraes128.keySize());
  ctraes128.setIV(ivAlice, ctraes128.keySize());
  ctraes128.encrypt(ciphertext, message, sizeof(message));

  sha256.resetHMAC(keyAliceMac, sizeof(keyAliceMac));
  sha256.update(message, sizeof(message));
  sha256.finalizeHMAC(keyAliceMac, sizeof(keyAliceMac), tag, sizeof(tag));
  b = micros();
  unsigned long clockcycle;
  clockcycle = microsecondsToClockCycles(b-a);
  Serial.print("ECIES (Alice) in: "); Serial.println(clockcycle);


  c = micros();
  r = uECC_shared_secret2(publicAlice1, privateBob1, pointBob1, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }

  sha256.reset();
  sha256.update(pointBob1, sizeof(pointBob1));
  sha256.finalize(hash2, sizeof(hash2));

  memcpy(keyBobEnc, hash2, sizeof(keyBobEnc));
  memcpy(keyBobMac, hash2 + 16, sizeof(keyBobMac));

  ctraes128.setKey(keyBobEnc, ctraes128.keySize());
  ctraes128.setIV(ivBob, ctraes128.keySize());
  ctraes128.decrypt(messageBob, ciphertext, sizeof(messageBob));

  sha256.resetHMAC(keyBobMac, sizeof(keyBobMac));
  sha256.update(messageBob, sizeof(messageBob));
  sha256.finalizeHMAC(keyBobMac, sizeof(keyBobMac), tagBob, sizeof(tagBob));

  if (memcmp(tagBob, tag, 16) != 0) {
    Serial.print("Message IS NOT Authenticated!\n");
  } else {
    Serial.print("Message is Authenticated\n");
  }
  d = micros();
  unsigned long clockcycle2;
  clockcycle2 = microsecondsToClockCycles(d-c);
  Serial.print("ECIES (Bob) in: "); Serial.println(clockcycle2);





}
