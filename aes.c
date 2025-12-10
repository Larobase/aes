#include "aes.h"
#include <stdio.h>
#include <string.h>

const uint8_t mixMat[16] = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02};

const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

const uint8_t sboxtab[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

void AESEncrypt(uint8_t ciphertext[DATA_SIZE], uint8_t plaintext[DATA_SIZE], uint8_t key[DATA_SIZE]) {

  // Initialisation et conversion des données
  uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE];
  MessageToState(state, plaintext);

  uint8_t master_key[STATE_ROW_SIZE][STATE_COL_SIZE];
  MessageToState(master_key, key);

  uint8_t roundkeys[ROUND_COUNT + 1][STATE_ROW_SIZE][STATE_COL_SIZE];
  uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE];

  KeyGen(roundkeys, master_key);

  int round = 0;
  GetRoundKey(roundkey, roundkeys, round);
  AddRoundKey(state, roundkey);
  round++;

  // Rounds 1-9
  while (round < ROUND_COUNT) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);

    GetRoundKey(roundkey, roundkeys, round);
    AddRoundKey(state, roundkey);
    round++;
  }

  // Round 10
  SubBytes(state);
  ShiftRows(state);

  GetRoundKey(roundkey, roundkeys, round);
  AddRoundKey(state, roundkey);

  // Conversion
  StateToMessage(ciphertext, state);
}

void AddRoundKey(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE]) {
  for (int i = 0; i < STATE_ROW_SIZE; i++) {
    for (int j = 0; j < STATE_COL_SIZE; j++) {
      state[i][j] ^= roundkey[i][j];
    }
  }
}

void SubBytes(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
  for (int i = 0; i < STATE_ROW_SIZE; i++) {
    for (int j = 0; j < STATE_COL_SIZE; j++) {
      state[i][j] = sboxtab[state[i][j]];
    }
  }
}

void ShiftRows(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {

  // Implémentation standard propre du décalage
  uint8_t tmp[STATE_COL_SIZE];

  // Ligne 0: Ne change pas

  // Ligne 1: décalage de 1 à gauche
  for (int j = 0; j < 4; j++)
    tmp[j] = state[1][(j + 1) % 4];
  for (int j = 0; j < 4; j++)
    state[1][j] = tmp[j];

  // Ligne 2: décalage de 2 à gauche
  for (int j = 0; j < 4; j++)
    tmp[j] = state[2][(j + 2) % 4];
  for (int j = 0; j < 4; j++)
    state[2][j] = tmp[j];

  // Ligne 3: décalage de 3 à gauche
  for (int j = 0; j < 4; j++)
    tmp[j] = state[3][(j + 3) % 4];
  for (int j = 0; j < 4; j++)
    state[3][j] = tmp[j];
}

void MixColumns(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
  for (int i = 0; i < STATE_COL_SIZE; i++) {

    // Isolement de chaque colonne
    uint8_t column[STATE_COL_SIZE];
    for (int j = 0; j < STATE_ROW_SIZE; j++) {
      column[j] = state[j][i];
    }

    MCMatrixColumnProduct(column);

    // Remise en commun
    for (int j = 0; j < STATE_ROW_SIZE; j++) {
      state[j][i] = column[j];
    }
  }
}

// Fonction de génération complète des clés
void KeyGen(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t master_key[STATE_ROW_SIZE][STATE_COL_SIZE]) {
  // Round 0 est la clé maitre
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      roundkeys[0][i][j] = master_key[i][j];
    }
  }

  // Génération des 10 autres round keys
  for (int i = 1; i <= ROUND_COUNT; i++) {
    ColumnFill(roundkeys, i);
    OtherColumnsFill(roundkeys, i);
  }
}

void ColumnFill(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round) {
  uint8_t temp[4];

  // Prend la dernière colonne du round précédent
  for (int i = 0; i < 4; i++) {
    temp[i] = roundkeys[round - 1][i][3];
  }

  // RotWord
  uint8_t t = temp[0];
  temp[0] = temp[1];
  temp[1] = temp[2];
  temp[2] = temp[3];
  temp[3] = t;

  // SubWord
  for (int i = 0; i < 4; i++) {
    temp[i] = sboxtab[temp[i]];
  }

  // XOR avec Rcon (seulement sur le premier octet de la colonne)
  temp[0] ^= rcon[round - 1];

  // XOR avec la première colonne du round précédent
  for (int i = 0; i < 4; i++) {
    roundkeys[round][i][0] = roundkeys[round - 1][i][0] ^ temp[i];
  }
}

void OtherColumnsFill(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round) {
  for (int col = 1; col < 4; col++) {
    for (int row = 0; row < 4; row++) {
      // Col actuelle = Col précédente du même round ^ Col même position round précédent
      roundkeys[round][row][col] = roundkeys[round][row][col - 1] ^ roundkeys[round - 1][row][col];
    }
  }
}

void GetRoundKey(uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      roundkey[i][j] = roundkeys[round][i][j];
    }
  }
}

void MessageToState(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t message[DATA_SIZE]) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      // Standard AES : state[row][col] = message[col * 4 + row]
      state[j][i] = message[i * 4 + j];
    }
  }
}

void StateToMessage(uint8_t message[DATA_SIZE], uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      // Standard AES : message[col * 4 + row] = state[row][col]
      message[i * 4 + j] = state[j][i];
    }
  }
}

void MCMatrixColumnProduct(uint8_t colonne[STATE_COL_SIZE]) {
  uint8_t tmp[STATE_COL_SIZE];

  for (int i = 0; i < STATE_COL_SIZE; i++) {
    uint8_t res = 0x00;
    for (int j = 0; j < STATE_COL_SIZE; j++) {
      uint8_t m = mixMat[i * 4 + j];
      res ^= gmul(m, colonne[j]);
    }
    tmp[i] = res;
  }

  for (int i = 0; i < STATE_COL_SIZE; i++)
    colonne[i] = tmp[i];
}

uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  while (b) {
    if (b & 1)
      p ^= a;
    uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi)
      a ^= 0x1b;
    b >>= 1;
  }
  return p;
}