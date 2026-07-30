#include "../header_files/interface.h"
#include "../header_files/database.h"
#include "../header_files/protocol.h"
#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <chrono>
#include <format>
using namespace std;

//code for the interface-like in the project

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

//before login
void serviceEntry(){
    std::cout << "\n" << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_MAGENTA << "            HELLO! WELCOME             " << RESET << "\n";
    std::cout << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_WHITE << "Available options:\n" << RESET;
    std::cout << BOLD_CYAN<< " 1. login    " << RESET << "- Request your balance\n";
    std::cout << BOLD_CYAN << " 2. verify     " << RESET << "- Verify Timestamp\n";
    std::cout << BOLD_CYAN << " 3. exit       " << RESET << "- Close the service\n";
    std::cout << BOLD_MAGENTA << "----------------------------------------" << RESET << "\n";
    std::cout << BOLD_GREEN << "Insert your choice: " << RESET;
}

//after login
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

void timestampCompleted(const std::string& filename, uint64_t raw_time) {
    std::cout << "\n" << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_MAGENTA << "           TIMESTAMP COMPLETED            " << RESET << "\n";
    std::cout << BOLD_MAGENTA << "========================================" << RESET << "\n";
    
    std::cout << BOLD_CYAN << " File: " << RESET << filename << "\n";
    std::cout << BOLD_CYAN << " Status: " << RESET << BOLD_GREEN << "Successfully stamped and verified" << RESET << "\n";
    
    try {
        std::chrono::seconds duration_secs(raw_time);
        std::chrono::system_clock::time_point tp(duration_secs);
        auto local_time = std::chrono::zoned_time{std::chrono::current_zone(), tp};
        
        std::cout << BOLD_CYAN << " Timestamp: " << RESET << std::format("{:%Y-%m-%d %H:%M:%S}", local_time) << "\n";
    } catch (...) {
        std::cout << BOLD_CYAN << " Timestamp: " << RESET << raw_time << " (Raw)\n";
    }
    std::cout << BOLD_MAGENTA << "========================================" << RESET << "\n";
}

//balance request
void balance(const TimestampInfo& info){
    std::cout << "\n" << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_MAGENTA << "           YOUR BALANCE             " << RESET << "\n";
    std::cout << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_CYAN << " Remaining Timestamps  " << RESET << info.remaining << "\n";
    std::cout << BOLD_CYAN<< " Used Timestamps    " << RESET << info.consumed << "\n" ;
    std::cout << BOLD_CYAN << " Total Timestamps  " << RESET << info.total << "\n";
    std::cout << BOLD_MAGENTA << "----------------------------------------" << RESET << "\n";
}



//verification request
void verificationCompleted(const string& timestamp_str){ //add the filename
    std::cout << "\n" << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_MAGENTA << "           VERIFICATION COMPLETED             " << RESET << "\n";
    std::cout << BOLD_MAGENTA << "========================================" << RESET << "\n";
    std::cout << BOLD_CYAN << "the file is authentic" << RESET << "\n";
    std::cout << BOLD_CYAN << "It was marked by the server correctly" << RESET << "\n";
    try {
        uint64_t raw_time = std::stoull(timestamp_str);
        std::chrono::seconds duration_secs(raw_time);
        std::chrono::system_clock::time_point tp(duration_secs);
        auto local_time = std::chrono::zoned_time{std::chrono::current_zone(), tp};
        
        std::cout << BOLD_GREEN << "Timestamp: " << std::format("{:%Y-%m-%d %H:%M:%S}", local_time) << RESET << "\n";
    } catch (...) {
        std::cout << BOLD_RED << "Timestamp: " << timestamp_str << " (Raw)" << RESET << "\n";
    }

    std::cout << BOLD_MAGENTA << "----------------------------------------" << RESET << "\n";

}