#include <uECC.h>

#include <stdio.h>
#include <avr/io.h>
#include <avr/interrupt.h>

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



#ifndef F_CPU
#warning "F_CPU is not defined, set to 16MHz per default."
#define F_CPU 16000000
#endif

#define BAUD 9600
#include <util/setbaud.h>

#ifndef UCSRB
# ifndef UDRE
# define UDRE UDRE0
# define RXEN RXEN0
# define TXEN TXEN0
# endif
# ifdef UCSR0A /* ATmega128 */
# define UCSRA UCSR0A
# define UCSRB UCSR0B
# define UBRRL UBRR0L
# define UBRRH UBRR0H
# define UDR UDR0
# else /* ATmega8 */
# define UCSRA USR
# define UCSRB UCR
# endif
#endif
#ifndef UBRR
# define UBRR UBRRL
#endif 

static char serial_initialized = 0;

void serial_init(void)   
{
  UBRRH = UBRRH_VALUE;
  UBRRL = UBRRL_VALUE;
  /* Enable */
  UCSRB = (1 << RXEN) | (1 << TXEN);
}

void serial_write(unsigned char c)
{
  if(!serial_initialized)
  {
    serial_init();
    serial_initialized = 1;
  }
  while (!(UCSRA & (1 << UDRE))){};
  UDR = c;
}

void print(const char *s)
{
  while(*s != 0)
  {
    serial_write(*s);
    s++;
  }
}

void printllu(unsigned long long x)
{
  char str[24];
  int i = 22;
  str[23]=0;
  while(x>0)
  {
    str[i] = (char)((x%10)+48);
    i--;
    x = x/10;
  }
  print(str+i+1);
}

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}


static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

void print_bench(const char *s, unsigned long long *t, unsigned int tlen)
{
  char outs[25];
  unsigned int i=0;
  while((i < 23) && (s[i] != 0))
  {
    outs[i] = s[i];
    i++;
  }
  outs[i++] = ':';
  for( ;i<24;i++)
    outs[i] = ' ';
  outs[i] = 0;
  print(outs);

  for(i=0;i<tlen-1;i++)
    t[i] = t[i+1]-t[i];
  printllu(median(t,tlen-1));
  print("\r\n");
}

static unsigned long long ticks;
static unsigned char init2 = 0;

static void cpucycles_init(void)
{
  ticks = 0;
#if defined (__AVR_ATmega128__)
  TCCR1B = (1 << CS12); // Set up timer 
  TIMSK |= (1 << TOIE1);
#else
  TCCR0B = (1 << CS00); // Set up timer 
  TCCR1B = (1 << CS12); // Set up timer 
  TIMSK1 |= (1 << TOIE1);
#endif  
  TCNT0 = 0;
  TCNT1 = 0;
  sei(); // Enable global overflows
  init2 = 1;
}

// Interrupt handler, called automatically on
// TIMER1 overflow
ISR(TIMER1_OVF_vect)
{
  ticks += (1UL << 24);
}

unsigned long long cpucycles(void)
{
  if(!init2)
    cpucycles_init();
  unsigned long long rh = TCNT1;
  unsigned long long rl = TCNT0;
  return ticks | (rh << 8) | rl; 
}





void setup() {
  //Serial.begin(9600);
  //Serial.print("Testing ecc\n");
  uECC_set_rng(&RNG);
   #define NTIMINGS 3
}

void loop() {
  const struct uECC_Curve_t * curve = uECC_secp256r1();
  uint8_t private1[33];
  uint8_t private2[33];
  
  uint8_t public1[64];
  uint8_t public2[64];
  
  uint8_t secret1[32];
  uint8_t secret2[32];

  uint8_t hash[32] = {0};
  uint8_t sig[64] = {0};

  unsigned long long t[NTIMINGS];
  int i;
  
  //unsigned long a = millis();
  for(i=0;i<NTIMINGS;i++)
  {
    t[i] = cpucycles();
    uECC_make_key(public1, private1, curve);

  }

  print_bench("Made key 1 in",t,NTIMINGS);
  //unsigned long b = millis();
  
  //Serial.print("Made key 1 in "); Serial.println(b-a);
  //a = millis();

  for(i=0;i<NTIMINGS;i++)
  {
    t[i] = cpucycles();
    uECC_make_key(public2, private2, curve);

  }
  print_bench("Made key 2 in",t,NTIMINGS);
  //b = millis();
  //Serial.print("Made key 2 in "); Serial.println(b-a);

  //a = millis();
  int r;
  for(i=0;i<NTIMINGS;i++)
  {
    t[i] = cpucycles();
    r = uECC_shared_secret(public2, private1, secret1, curve);

  }
  print_bench("Shared secret 1 in ",t,NTIMINGS);
  
  //b = millis();
  //Serial.print("Shared secret 1 in "); Serial.println(b-a);
  if (!r) {
   // Serial.print("shared_secret() failed (1)\n");
  }

 // a = millis();
 for(i=0;i<NTIMINGS;i++)
  {
    t[i] = cpucycles();
    r = uECC_shared_secret(public1, private2, secret2, curve);

  }
  print_bench("Shared secret 2 in ",t,NTIMINGS);
  //b = millis();
  //Serial.print("Shared secret 2 in "); Serial.println(b-a);
  if (!r) {
    //Serial.print("shared_secret() failed (2)\n");
  }
    
  if (memcmp(secret1, secret2, 32) != 0) {
    //Serial.print("Shared secrets are not identical!\n");
  } else {
    //Serial.print("Shared secrets are identical\n");
  }
 // a = millis();

  
  for(i=0;i<NTIMINGS;i++)
  {
    t[i] = cpucycles();
    if (!uECC_sign(private1, hash, sizeof(hash), sig, curve)) {
     // printf("uECC_sign() failed\n");
    }
  }

  print_bench("TESTING Signing",t,NTIMINGS);
  
           
 // b = millis();
  //Serial.print("Sign: "); Serial.println(b-a);

  //a = millis();

  for(i=0;i<NTIMINGS;i++)
  {
    t[i] = cpucycles();
    if (!uECC_verify(public1, hash, sizeof(hash), sig, curve)) {
     // printf("uECC_verify() failed\n");
  } 
  }

  print_bench("TESTING Verifying",t,NTIMINGS);
  
  
  
  //b = millis();
  //Serial.print("Verify: "); Serial.println(b-a);
}

