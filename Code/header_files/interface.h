#ifndef CLI_UI_H
#define CLI_UI_H

#include <iostream>
#include <string>
#include "../header_files/database.h"

const std::string RESET = "\033[0m";
const std::string BOLD_RED     = "\033[1;31m";
const std::string BOLD_GREEN   = "\033[1;32m";
const std::string BOLD_YELLOW  = "\033[1;33m";
const std::string BOLD_BLUE    = "\033[1;34m";
const std::string BOLD_MAGENTA = "\033[1;35m";
const std::string BOLD_CYAN    = "\033[1;36m";
const std::string BOLD_WHITE   = "\033[1;37m";
const std::string BOLD_ORANGE        = "\033[1;38;5;208m";
const std::string BOLD_PINK          = "\033[1;38;5;206m";
const std::string BOLD_PURPLE        = "\033[1;38;5;129m";
const std::string BOLD_TEAL          = "\033[1;38;5;30m";    // Verde acqua
const std::string BOLD_LIME          = "\033[1;38;5;118m";   // Verde lime
const std::string BOLD_GOLD          = "\033[1;38;2;255;215;0m";
const std::string BOLD_BROWN         = "\033[1;38;5;130m";


void printBanner(const std::string& message, const std::string& color = BOLD_CYAN);
void serviceEntry();
void homeMenu();
void timestampCompleted(const std::string& filename, uint64_t raw_time);
void balance(const TimestampInfo& info);
void verificationCompleted(const std::string& timestamp_str);

#endif 