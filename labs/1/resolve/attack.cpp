#include "cesar.h"
#include <fstream>
void statistical_decrypt(const std::string& enc, const std::string& ref_json, const std::string& out) {
  double fe[ASCII_SIZE] = {};
  if (!load_statistics_json(ref_json, fe)) return;
  unsigned long long cc[ASCII_SIZE] = {};
  std::ifstream fin(enc, std::ios::binary);
  if (!fin) return;
  char ch;
  unsigned long long tot = 0;
  while (fin.get(ch)) {
    int u = static_cast<unsigned char>(ch);
    if (u < ASCII_SIZE) cc[u]++;
    tot++;
  }
  double fc[ASCII_SIZE] = {};
  if (tot > 0) {
    for (int i = 0; i < ASCII_SIZE; ++i) fc[i] = static_cast<double>(cc[i]) / static_cast<double>(tot);
  }
  int bestk = 0;
  double best = -1.0;
  for (int k = 0; k < ASCII_SIZE; ++k) {
    double s = 0.0;
    for (int i = 0; i < ASCII_SIZE; ++i) s += fe[i] * fc[(i + k) % ASCII_SIZE];
    if (s > best) { best = s; bestk = k; }
  }
  fin.clear();
  fin.seekg(0, std::ios::beg);
  std::ofstream fout(out, std::ios::binary);
  if (!fout) return;
  while (fin.get(ch)) {
    int x = static_cast<unsigned char>(ch);
    int y = (x - bestk + ASCII_SIZE) % ASCII_SIZE;
    fout.put(static_cast<char>(y));
  }
}
