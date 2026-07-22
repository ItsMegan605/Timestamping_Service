#include "../header_files/interface.h"
#include "../header_files/database.h"
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
    std::cout << BOLD_CYAN<< " 1. balance    " << RESET << "- Request your balance\n";
    std::cout << BOLD_CYAN << " 2. timestamp  " << RESET << "- Request timestamps to the server\n";
    std::cout << BOLD_CYAN << " 3. verify     " << RESET << "- Verify Timestamp\n";
    std::cout << BOLD_CYAN << " 4. exit       " << RESET << "- Close the service\n";
    std::cout << BOLD_MAGENTA << "----------------------------------------" << RESET << "\n";
    std::cout << BOLD_GREEN << "Insert your choice: " << RESET;
}

void balance(const TimestampInfo& info){
    std::cout << "\n" << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_MAGENTA << "           YOUR BALANCE             " << RESET << "\n";
    std::cout << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_CYAN << " Remaining Timestamps  " << RESET << info.remaining << "\n";
    std::cout << BOLD_CYAN<< " Used Timestamps    " << RESET << info.consumed << "\n" ;
    std::cout << BOLD_CYAN << " Total Timestamps  " << RESET << info.total << "\n";
    std::cout << BOLD_MAGENTA << "----------------------------------------" << RESET << "\n";
}