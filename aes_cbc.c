#include "aes.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_BUFFER_SIZE 256

// Fonction utilitaire pour le XOR de deux blocs de 16 octets
void xor_blocks(uint8_t *dest, const uint8_t *src1, const uint8_t *src2) {
  for (int i = 0; i < 16; i++) {
    dest[i] = src1[i] ^ src2[i];
  }
}

void AES_CBC_Encrypt(uint8_t *ciphertext, uint8_t *plaintext, size_t length, uint8_t *key, uint8_t *iv) {

  // Vérification basique de l'alignement (pour simplifier, on ignore le Padding PKCS7 ici)
  if (length % 16 != 0) {
    printf("Erreur: La longueur du message doit etre un multiple de 16 octets pour cet exemple.\n");
    return;
  }

  uint8_t current_iv[16];
  uint8_t block_input[16];
  uint8_t block_output[16];

  // Pour le premier tour, le "bloc précédent" est l'IV
  memcpy(current_iv, iv, 16);

  for (size_t i = 0; i < length; i += 16) {
    // Récupérer le bloc de plaintext actuel
    uint8_t *current_plaintext_block = &plaintext[i];

    // XOR : Input = Plaintext ^ Previous_Ciphertext (ou IV)
    xor_blocks(block_input, current_plaintext_block, current_iv);

    // Chiffrement AES (Core)
    AESEncrypt(block_output, block_input, key);

    // Copier le résultat dans le buffer de sortie
    memcpy(&ciphertext[i], block_output, 16);

    // Mise à jour de la chaîne : Le résultat devient l'IV du prochain tour
    memcpy(current_iv, block_output, 16);
  }
}

int main(int argc, char *argv[]) {
  // Vérification des arguments
  if (argc < 2) {
    printf("Usage: %s \"Texte a chiffrer\"\n", argv[0]);
    return 1;
  }

  uint8_t key[16] = {
      0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  uint8_t iv[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  // Récupérration de l'argument (la chaîne à chiffrer)
  uint8_t *text = (uint8_t *)argv[1];
  size_t len = strlen((char *)text);

  if (len + 16 > MAX_BUFFER_SIZE) {
    printf("Erreur : Le texte est trop long pour le buffer fixe (%d octets max).\n", MAX_BUFFER_SIZE);
    return 1;
  }

  uint8_t padded_text[MAX_BUFFER_SIZE];

  // Calcul du padding nécessaire
  uint8_t pad_val = 16 - (len % 16);
  size_t padded_len = len + pad_val;

  // Remplissage du buffer avec texte + padding
  for (size_t i = 0; i < padded_len; i++) {
    if (i < len) {
      padded_text[i] = text[i];
    } else {
      padded_text[i] = pad_val;
    }
  }

  uint8_t encrypted[MAX_BUFFER_SIZE];

  printf("Plaintext (%zu bytes): %s\n", len, text);

  printf("Lancement AES CBC...\n");
  AES_CBC_Encrypt(encrypted, padded_text, padded_len, key, iv);

  printf("Ciphertext (Hex):\n");
  for (size_t i = 0; i < padded_len; i++) {
    printf("%02x", encrypted[i]);
    if ((i + 1) % 16 == 0)
      printf("\n");
  }
  printf("\n");

  return 0;
}