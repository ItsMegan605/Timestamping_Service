#include "../header_files/interface.h"
#include <iostream>
#include <unistd.h>
#include <cstdlib>

using namespace std;

void printBanner(const std::string& message, const std::string& color) {
    int padding = 4;
    int width = message.length() + padding;
    string border(width, '-');

    cout << color << "\n";
    cout << " +" << border << "+\n";
    cout << " |  " << message << "  |\n";
    cout << " +" << border << "+\n";
    cout << RESET << std::endl;
}

void homeMenu(){
    std::cout << "\n" << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_MAGENTA << "            HOME MENU             " << RESET << "\n";
    std::cout << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_WHITE << "Available options:\n" << RESET;
    std::cout << BOLD_CYAN<< " 1. balance    " << RESET << "- Requeste your balance\n";
    std::cout << BOLD_CYAN << " 2. timestamp  " << RESET << "- Requeste timestamps to the servere\n";
    std::cout << BOLD_CYAN << " 3. verify     " << RESET << "- Verofy Timestamp\n";
    std::cout << BOLD_CYAN << " 4. exit       " << RESET << "- Close the service\n";
    std::cout << BOLD_MAGENTA << "----------------------------------------" << RESET << "\n";
    std::cout << BOLD_GREEN << "Insert your choice: " << RESET;
}