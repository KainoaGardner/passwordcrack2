#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20; // Maximum any password will be
const int HASH_LEN = 33; // Length of MD5 hash strings

// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
char *tryWord(char *plaintext, char *hashFilename) {
  // Hash the plaintext
  char *hash = md5(plaintext, strlen(plaintext));

  // Open the hash file
  FILE *hashFile = fopen(hashFilename, "r");
  if (!hashFile) {
    printf("Can't open %s for reading\n", hashFilename);
    return NULL;
  }

  // Loop through the hash file, one line at a time.
  char line[HASH_LEN];
  while (fgets(line, HASH_LEN, hashFile) != NULL) {
    // trim newline
    char *nl = strchr(line, '\n');
    if (nl)
      *nl = '\0';

    // compare hash to line hash
    if (strcmp(hash, line) == 0) {
      fclose(hashFile);
      return hash;
    }
  }

  // free hash closefile
  free(hash);
  fclose(hashFile);
  return NULL;
}

int main(int argc, char *argv[]) {
  // check args
  if (argc < 3) {
    fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
    exit(1);
  }

  // Open the dictionary file for reading.
  FILE *dictFile = fopen(argv[2], "r");
  if (!dictFile) {
    fprintf(stderr, "Can't open %s for reading\n", argv[2]);
    exit(1);
  }

  // check each word in dictionary file compared to hashfile
  int cracked = 0;
  char word[PASS_LEN];
  while (fgets(word, PASS_LEN, dictFile) != NULL) {
    // trim newline
    char *nl = strchr(word, '\n');
    if (nl)
      *nl = '\0';

    // try word with hashfile
    char *wordHash = tryWord(word, argv[1]);
    if (wordHash) {
      printf("%s %s\n", wordHash, word);
      free(wordHash);
      cracked++;
    }
  }

  printf("%d hashes cracked!\n", cracked);
  fclose(dictFile);
  return 0;
}
