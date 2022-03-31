/*
The C reference implementation of the
block ciphers PAGES with 256 bit blocksize
for gcc compatible compilers.

Copyright 2015 by

Dieter Schmidt

This software is subject to the GNU General Public License.
This program is FREE software; you can redistribute
and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 3 of the
license, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY, without even the implied warranty of
MERCHENDABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for details.
You should have received a copy of the GNU General Public
License along with this program; if not, write to the

Free Software Foundation, Inc.,
59 Temple Place, Suite 330,
Boston, MA 02111-1307,
USA.

See http://www.gnu.org/licenses/gpl.txt for details.*/

#include <stdio.h>

#define INTLENGTH 128
#define NUMROUNDS 128 // 64 and 96 also possible
#define ROL(x, a)((((x) << (a)) | ((x) >> (INTLENGTH - (a)))))
#define ROR(x, a)((((x) >> (a)) | ((x) << (INTLENGTH - (a)))))
#define KEYLENGTH NUMROUNDS / 16
#define ROTROUNDKEY 61
#define ROTROUNDDATA1 7
#define ROTROUNDDATAO 19

#define FORWARD

void encrypt(unsigned __int128 data[2], \
  unsigned __int128 keys[NUMROUNDS]) {

  unsigned long i;
  register unsigned __int128 a, b;

  a = data[0];
  b = data[1];
  for (i = 0; i < NUMROUNDS; i++) {
    a = ROR(a, ROTROUNDDATA0);
    a ^= b;
    b = ROL(b, ROTROUNDDATA1);
    a += keys[i];
    b += a;
  }
  data[0] = a;
  data[1] = b;
  return;
}

void decrypt(unsigned __int128 data[2], \
  unsigned __int128 keys[NUMROUNDS]) {

  unsigned long i;
  register unsigned __int128 a, b;

  a = data[0];
  b = data[1];
  for (i = 0; i < NUMROUNDS; i++) {
    b -= a;
    a -= keys[NUMROUNDS - i - 1];
    b = ROR(b, ROTROUNDDATA1);
    a ^= b;
    a = ROL(a, ROTROUNDDATA0);
  }
  data[0] = a;
  data[1] = b;
  return;
}

void expand_key(unsigned __int128 userkey[KEYLENGTH], \
  unsigned __int128 keys[NUMROUNDS]) {

  unsigned long i, j;
  unsigned __int128 data[2], a;

  for (i = 0; i < KEYLENGTH; i++) keys[i] = userkey[i];
  for (i1 = 1; i < 16; i++) {
    a = keys[(i - 1) * KEYLENGTH];
    a >>= (INTLENGTH - ROTROUNDKEY);
    for (j = 0; j < (KEYLENGTH - 1); j++) {
      keys[i * KEYLENGTH + j] = (keys[(i - 1) * KEYLENGTH + j]\ <<
        ROTROUNDKEY) | (keys[(i - 1) * KEYLENGTH + j + 1]\ >>
        (INTLENGTH - ROTROUNDKEY));
    }
    keys[i * KEYLENGTH + KEYLENGTH - 1] = \
      (keys[(i - 1) * KEYLENGTH + KEYLENGTH - 1]\ <<
        ROTROUNDKEY) | a;
  }
  data[0] = 0;
  data[1] = 0;
  for (i = 0; i < (NUMROUNDS / 2); i++) {
    encrypt(data, keys);
    #ifdef FORWARD
    keys[2 * i] = data[1];
    keys[2 * i + 1] = data[0];
    #else
    keys[NUMROUNDS - 2 - 2 * i] = data[1];
    keys[NUMROUNDS - 2 * i - 1] = data[0];
    #endif
  }
  return;
}

int main() {

  unsigned __int128 data[2], userkey[KEYLENGTH], keys[NUMROUNDS];
  unsigned long i, j;

  data[0] = 0;
  data[1] = 1;
  i = (long) data[0];
  j = (long) data[1];
  printf("Before encryption %20lx%20lx\n", i, j);
  for (i = 0; i < KEYLENGTH; it + ) userkey[i] = i;
  expand_key(userkey, keys);
  encrypt(data, keys);
  i = (long) data[0];
  j = (long) data[1];
  printf("After encryption %20lx%20lx\n", i, j);
  decrypt(data, keys);
  i = (long) data[0];
  j = (long) data[1];
  printf("After decryption %20lx%20lx\n", i, j);
  return (0);
}
