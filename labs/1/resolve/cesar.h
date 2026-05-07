#ifndef CESAR_H
#define CESAR_H
#include <string>
constexpr int ASCII_SIZE = 256;
void cesar(const std::string& in, const std::string& out, int key, int mode);
void save_statistics_json(const std::string& in, const std::string& out);
bool load_statistics_json(const std::string& path, double freq[ASCII_SIZE]);
void statistical_decrypt(const std::string& enc, const std::string& ref_json, const std::string& out);
#endif
