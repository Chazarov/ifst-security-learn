#ifndef CESAR_H
#define CESAR_H
#include <string>
extern const int ASCII_SIZE;
void cesar(const std::string& in, const std::string& out, int key, int mode);
void save_statistics_json(const std::string& in, const std::string& out);
bool load_statistics_json(const std::string& path, double freq[256]);
void statistical_decrypt(const std::string& enc, const std::string& ref_json, const std::string& out);
#endif
