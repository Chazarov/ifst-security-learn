#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

const int ASCII_SIZE = 256;

void code(std::string input_path, std::string output_path, int key, int mode) {
    std::ofstream output_file(output_path);
    std::ifstream input_file(input_path);

    if (input_file.is_open() && output_file.is_open()) {
        char c;
        while (input_file.get(c)) {
            int ascii_code =static_cast<unsigned char>(c);
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

void get_analize(std::string input_path, std::string output_path) {
    std::ifstream input_file(input_path);
    std::ofstream output_file(output_path);
    
    int symbols_count = 0;
    int counts[ASCII_SIZE] = {}; 

    if (input_file.is_open()) {
        char c;
        while (input_file.get(c)) {
            symbols_count++;
            int ascii_code = static_cast<unsigned char>(c);
            if (ascii_code < ASCII_SIZE) counts[ascii_code]++;
        }
    }
    input_file.close();
    if (output_file.is_open()) {
	    output_file << "Всего символов: " << symbols_count << std::endl << std::endl;
	    
	    for(int i = 0; i < ASCII_SIZE; i++) {
	        if (counts[i] > 0) {
	            int percent_times_100 = (counts[i] * 10000 + symbols_count / 2) / symbols_count;
				int whole = percent_times_100 / 100;
				int decimals = percent_times_100 % 100;
				
				output_file << i << ". '" << (char)(i) << "' -- " << counts[i] << " -- " 
				            << whole << "." 
				            << (decimals < 10 ? "0" : "") << decimals << "%\n";
	        }
	    }
	} else{
		std::cout << "Error";
	}
    
    
    output_file.close();
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
	
	if(mode == 0)get_analize(input_path, "statistic_enc.txt");
	else get_analize(input_path, "statistic_dec.txt");
		
	
    code(input_path, output_path, key, mode);
    return 0;
}
