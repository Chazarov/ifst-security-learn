#include "cesar.h"
#include <cstdlib>
#include <iostream>
#include <string>
static void usage() {
  std::cout
      << "cesar stat <in> <out.json>\n"
         "cesar enc <in> <out> <key 0-255>\n"
         "cesar dec <in> <out> <key 0-255>\n"
         "cesar decstat <in_enc> <ref.json> <out>\n";
}
int main(int argc, char** argv) {
  if (argc < 2) { usage(); return 1; }
  std::string cmd = argv[1];
  if (cmd == "stat") {
    if (argc != 4) { usage(); return 1; }
    save_statistics_json(argv[2], argv[3]);
    return 0;
  }
  if (cmd == "enc") {
    if (argc != 5) { usage(); return 1; }
    int key = std::stoi(argv[4]);
    if (key < 0 || key >= ASCII_SIZE) { usage(); return 1; }
    cesar(argv[2], argv[3], key, 0);
    return 0;
  }
  if (cmd == "dec") {
    if (argc != 5) { usage(); return 1; }
    int key = std::stoi(argv[4]);
    if (key < 0 || key >= ASCII_SIZE) { usage(); return 1; }
    cesar(argv[2], argv[3], key, 1);
    return 0;
  }
  if (cmd == "decstat") {
    if (argc != 5) { usage(); return 1; }
    statistical_decrypt(argv[2], argv[3], argv[4]);
    return 0;
  }
  usage();
  return 1;
}
