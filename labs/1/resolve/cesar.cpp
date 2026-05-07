#include "cesar.h"
#include <fstream>
const int ASCII_SIZE = 256;
void cesar(const std::string& in, const std::string& out, int key, int mode) {
  std::ifstream fin(in, std::ios::binary);
  std::ofstream fout(out, std::ios::binary);
  if (!fin || !fout) return;
  char c;
  while (fin.get(c)) {
    int x = static_cast<unsigned char>(c);
    int y;
    if (mode == 0) y = (x + key) % ASCII_SIZE;
    else y = (x - key + ASCII_SIZE) % ASCII_SIZE;
    fout.put(static_cast<char>(y));
  }
}
