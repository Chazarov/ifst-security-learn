#include "cesar.h"
#include <fstream>

static int find_key_by_correlation(const double ref_freq[ASCII_SIZE], const double target_freq[ASCII_SIZE]) {
  int bestk = 0;
  double best = -1.0;
  for (int k = 0; k < ASCII_SIZE; ++k) {
    double s = 0.0;
    for (int i = 0; i < ASCII_SIZE; ++i) s += ref_freq[i] * target_freq[(i + k) % ASCII_SIZE];
    if (s > best) { best = s; bestk = k; }
  }
  return bestk;
}

void statistical_decrypt(const std::string& enc, const std::string& ref_json, const std::string& out) {
  double ref_freq[ASCII_SIZE] = {};
  if (!load_statistics_json(ref_json, ref_freq)) return;

  std::ifstream fin(enc, std::ios::binary);
  if (!fin) return;

  char ch;
  unsigned long long total_bytes = 0;
  unsigned long long char_counts[ASCII_SIZE] = {};
  while (fin.get(ch)) {
    int u = static_cast<unsigned char>(ch);
    if (u < ASCII_SIZE) char_counts[u]++;
    total_bytes++;
  }

  double target_freq[ASCII_SIZE] = {};
  if (total_bytes > 0) {
    for (int i = 0; i < ASCII_SIZE; ++i) target_freq[i] = static_cast<double>(char_counts[i]) / static_cast<double>(total_bytes);
  }

  int bestk = find_key_by_correlation(ref_freq, target_freq);

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
