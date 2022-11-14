#include "aes.c"

char encBuf[256] = {0}; // Let's make sure we have enough space for the encrypted string
char decBuf[256] = {0}; // Let's make sure we have enough space for the decrypted string
char plainBuf[256] = {0}; // Let's make sure we have enough space for the decrypted string
uint8_t pKey[16] = {0};
uint8_t IV[16] = {0};
uint8_t pKeyLen = 16;
uint8_t randomBuff[64] = {
  0x5f, 0x21, 0x62, 0x02, 0xf8, 0xe7, 0x4c, 0x4c,
  0xa7, 0xb7, 0x69, 0xae, 0x78, 0x5f, 0x21, 0xd6,
  0x5a, 0x1f, 0x38, 0xd8, 0xae, 0x80, 0x4e, 0x4b,
  0xad, 0x2e, 0x41, 0x89, 0xa3, 0x62, 0x08, 0x2b,
  0x6c, 0x59, 0xc9, 0x10, 0x7c, 0x09, 0x48, 0x03,
  0x8c, 0x66, 0x36, 0xe6, 0x4e, 0xc8, 0x7b, 0x53,
  0x53, 0x57, 0xd8, 0x59, 0x75, 0x3c, 0x4d, 0xd1,
  0xa6, 0x63, 0x15, 0x8f, 0x81, 0x6b, 0x5b, 0x19
};

void hexDump(uint8_t* buf, uint16_t len) {
  // Something similar to the Unix/Linux hexdump -C command
  // Pretty-prints the contents of a buffer, 16 bytes a row
  char alphabet[17] = "0123456789abcdef";
  uint16_t i, index;
  Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
  Serial.print(F("   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |\n"));
  for (i = 0; i < len; i += 16) {
    if (i % 128 == 0) Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
    char s[] = "|                                                | |                |\n";
    // pre-formated line. We will replace the spaces with text when appropriate.
    uint8_t ix = 1, iy = 52, j;
    for (j = 0; j < 16; j++) {
      if (i + j < len) {
        uint8_t c = buf[i + j];
        // fastest way to convert a byte to its 2-digit hex equivalent
        s[ix++] = alphabet[(c >> 4) & 0x0F];
        s[ix++] = alphabet[c & 0x0F];
        ix++;
        if (c > 31 && c < 128) s[iy++] = c;
        else s[iy++] = '.'; // display ASCII code 0x20-0x7F or a dot.
      }
    }
    index = i / 16;
    // display line number then the text
    if (i < 256) Serial.write(' ');
    Serial.print(index, HEX); Serial.write('.');
    Serial.print(s);
  }
  Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
}

void setup() {
  Serial.begin(115200);
  time_t timeout = millis();
  while (!Serial) {
    if ((millis() - timeout) < 5000) {
      delay(100);
    } else {
      break;
    }
  }
  delay(2000);
  Serial.printf("\nRAK3172 Software AES%d test!\n", (AES_KEYLEN * 8));

  char *msg = "Hello user! This is a plain text string!";
  uint8_t msgLen = strlen(msg);
  // please note dear reader – and you should RTFM – that this string's length isn't a multiple of 16.
  Serial.println("Plain text:");
  hexDump((unsigned char *)msg, msgLen);
  memcpy(pKey, "This_Is-A Key123", 16); // Not a very good one but okaaaay
  Serial.println("pKey:");
  hexDump(pKey, 16);

  uint16_t olen, counter = 0;
  double t0 = millis();
  while (millis() - t0 < 1000) {
    olen = encryptECB((uint8_t*)msg);
    counter++;
  }
  Serial.println("ECB Encoded:");
  hexDump((unsigned char *)encBuf, olen);
  Serial.printf("%d round / s\n", counter);
  memcpy(decBuf, encBuf, olen);

  t0 = millis();
  while (millis() - t0 < 1000) {
    olen = decryptECB((uint8_t*)decBuf, olen);
    counter++;
  }
  Serial.println("ECB Decoded:");
  hexDump((unsigned char *)encBuf, olen);
  Serial.printf("%d round / s\n", counter);

  memcpy(IV, randomBuff, 16);
  Serial.println("IV:");
  hexDump(IV, 16);
  strcpy(plainBuf, msg);
  counter = 0;
  t0 = millis();
  while (millis() - t0 < 1000) {
    encryptCBC((uint8_t*)plainBuf, strlen(msg), IV);
    counter++;
  }
  Serial.println("CBC Encoded:");
  hexDump((unsigned char *)encBuf, olen);
  Serial.printf("%d round / s\n", counter);
  memcpy(decBuf, encBuf, olen);
  counter = 0;
  t0 = millis();
  while (millis() - t0 < 1000) {
    decryptCBC((uint8_t*)encBuf, olen, IV);
    counter++;
  }
  Serial.println("CBC Decoded:");
  hexDump((unsigned char *)decBuf, olen);
  Serial.printf("%d round / s\n", counter);

  memcpy(IV, randomBuff + 16, 16);
  Serial.println("IV:");
  hexDump(IV, 16);
  strcpy(plainBuf, msg);
  counter = 0;
  t0 = millis();
  while (millis() - t0 < 1000) {
    encryptCBC((uint8_t*)plainBuf, strlen(msg), IV);
    counter++;
  }
  Serial.println("CBC Encoded:");
  hexDump((unsigned char *)encBuf, olen);
  Serial.printf("%d round / s\n", counter);
  memcpy(decBuf, encBuf, olen);
  counter = 0;
  t0 = millis();
  while (millis() - t0 < 1000) {
    decryptCBC((uint8_t*)encBuf, olen, IV);
    counter++;
  }
  Serial.println("CBC Decoded:");
  hexDump((unsigned char *)decBuf, olen);
  Serial.printf("%d round / s\n", counter);
}

void loop() {
}

int16_t decryptECB(uint8_t* myBuf, uint8_t olen) {
  uint8_t reqLen = 16;
  if (olen < reqLen) return -1;
  uint8_t len;
  // or just copy over
  memcpy(encBuf, myBuf, olen);
  len = olen;
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, pKey);
  uint8_t rounds = len / 16, steps = 0;
  for (uint8_t ix = 0; ix < rounds; ix++) {
    // void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
    AES_ECB_decrypt(&ctx, (uint8_t*)encBuf + steps);
    steps += 16;
    // decrypts in place, 16 bytes at a time
  } encBuf[steps] = 0;
  return len;
}

uint16_t encryptECB(uint8_t* myBuf) {
  // first ascertain length
  uint8_t len = strlen((char*)myBuf);
  uint16_t olen;
  struct AES_ctx ctx;
  olen = len;
  if (olen != 16) {
    if (olen % 16 > 0) {
      if (olen < 16) olen = 16;
      else olen += 16 - (olen % 16);
    }
  }
  memset(encBuf, (olen - len), olen);
  memcpy(encBuf, myBuf, len);
  encBuf[len] = 0;
  AES_init_ctx(&ctx, pKey);
  uint8_t rounds = olen / 16, steps = 0;
  for (uint8_t ix = 0; ix < rounds; ix++) {
    AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + steps));
    steps += 16;
    // encrypts in place, 16 bytes at a time
  }
  return olen;
}

int16_t encryptCBC(uint8_t* myBuf, uint8_t olen, uint8_t* Iv) {
  uint8_t rounds = olen / 16;
  if (rounds == 0) rounds = 1;
  else if (olen - (rounds * 16) != 0) rounds += 1;
  uint8_t length = rounds * 16;
  memset(encBuf, (length - olen), length);
  memcpy(encBuf, myBuf, olen);
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, pKey, Iv);
  AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encBuf, length);
  return length;
}

int16_t decryptCBC(uint8_t* myBuf, uint8_t olen, uint8_t* Iv) {
  uint8_t rounds = olen / 16;
  if (rounds == 0) rounds = 1;
  else if (olen - (rounds * 16) != 0) rounds += 1;
  uint8_t length = rounds * 16;
  // We *could* trust the user with the buffer length, but...
  // Let's just make sure eh?
  memcpy(decBuf, myBuf, olen);
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, pKey, Iv);
  AES_CBC_decrypt_buffer(&ctx, (uint8_t*)decBuf, length);
  return length;
}
