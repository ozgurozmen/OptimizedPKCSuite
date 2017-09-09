#include <uECC.h>

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
  Serial.print("Testing ecc\n");
  uECC_set_rng(&RNG);
}

void loop() {
  const struct uECC_Curve_t * curve = uECC_secp256r1();
  uint8_t private1[33];
  
  uint8_t public1[64];

  uint8_t hash[32] = {0};
  uint8_t sig[64] = {0};
  
  unsigned long a = micros();
  uECC_make_key(public1, private1, curve);
  unsigned long b = micros();
  unsigned long clockcycle;
  clockcycle = microsecondsToClockCycles(b-a);
  Serial.print("Made key 1 in "); Serial.println(clockcycle);

  memcpy(hash, public1, sizeof(hash));

  a = micros();
  if (!uECC_sign(private1, hash, sizeof(hash), sig, curve)) {
     // printf("uECC_sign() failed\n");
   }
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
