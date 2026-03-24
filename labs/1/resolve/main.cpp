#include <iostream>
#include <fstream>
#include <string>

const int ASCII_SIZE = 128;

void code(std::string input_path, std::string output_path, int key, int mode) {
    std::ofstream output_file(output_path);
    std::ifstream input_file(input_path);

    if (input_file.is_open() && output_file.is_open()) {
        char c;
        while (input_file.get(c)) {
            int ascii_code = static_cast<int>(c);
            int new_ascii_code;
            if (mode == 0)
                new_ascii_code = (ascii_code + key) % ASCII_SIZE;
            else if (mode == 1)
                new_ascii_code = (ascii_code - key + ASCII_SIZE) % ASCII_SIZE;

            char enc = static_cast<char>(new_ascii_code);
            output_file.put(enc);
        }
        input_file.close();
        output_file.close();
    }
}

int main(int argc, char** argv) {
    int key, mode;
    std::string input_path, output_path;

    std::cout << "Enter the path to the input file: ";
    std::getline(std::cin, input_path);
    std::cout << "Enter the path to the output file: ";
    std::getline(std::cin, output_path);
    std::cout << "Enter the mode: 0 - encode, 1 - decode: ";
    std::cin >> mode;
    while (true) {
        std::cout << "Enter the number from 0 to " << ASCII_SIZE - 1 << " (encoding key): ";
        std::cin >> key;
        if (key >= 0 && key < ASCII_SIZE)
            break;
        std::cout << "Error: key must be in [0, " << ASCII_SIZE - 1 << "]. Try again.\n";
    }

    code(input_path, output_path, key, mode);
    return 0;
}
