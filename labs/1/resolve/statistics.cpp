#include "cesar.h"
#include <fstream>
#include <iterator>
#include <sstream>
void save_statistics_json(const std::string& in, const std::string& out) {
  unsigned long long counts[256] = {};
  std::ifstream fin(in, std::ios::binary);
  if (!fin) return;
  char ch;
  unsigned long long n = 0;
  while (fin.get(ch)) {
    int u = static_cast<unsigned char>(ch);
    if (u < 256) counts[u]++;
    n++;
  }
  std::ofstream fo(out);
  if (!fo) return;
  fo << "{\"total\":" << n << ",\"c\":[";
  for (int i = 0; i < 256; ++i) {
    if (i) fo << ',';
    fo << counts[i];
  }
  fo << "]}\n";
}
bool load_statistics_json(const std::string& path, double freq[256]) {
  std::ifstream f(path);
  if (!f) return false;
  std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  long long cvals[256] = {};
  size_t a = s.find("\"c\"");
  if (a == std::string::npos) return false;
  size_t lb = s.find('[', a);
  if (lb == std::string::npos) return false;
  int idx = 0;
  for (size_t p = lb + 1; p < s.size() && idx < 256; ) {
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r' || s[p] == ',')) p++;
    if (p < s.size() && s[p] == ']') break;
    if (p >= s.size()) break;
    long long v = 0;
    int sign = 1;
    if (s[p] == '-') { sign = -1; p++; }
    for (; p < s.size() && s[p] >= '0' && s[p] <= '9'; p++) v = v * 10 + (s[p] - '0');
    v *= sign;
    cvals[idx++] = v;
  }
  if (idx != 256) return false;
  unsigned long long ssum = 0;
  for (int i = 0; i < 256; ++i) {
    if (cvals[i] < 0) return false;
    ssum += static_cast<unsigned long long>(cvals[i]);
  }
  if (ssum == 0) {
    for (int i = 0; i < 256; ++i) freq[i] = 0.0;
    return true;
  }
  for (int i = 0; i < 256; ++i) freq[i] = static_cast<double>(cvals[i]) / static_cast<double>(ssum);
  return true;
}
