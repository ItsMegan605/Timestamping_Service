#ifndef CLI_UI_H
#define CLI_UI_H

#include <iostream>
#include <string>

const std::string RESET = "\033[0m";
const std::string BOLD_RED     = "\033[1;31m";
const std::string BOLD_GREEN   = "\033[1;32m";
const std::string BOLD_YELLOW  = "\033[1;33m";
const std::string BOLD_BLUE    = "\033[1;34m";
const std::string BOLD_MAGENTA = "\033[1;35m";
const std::string BOLD_CYAN    = "\033[1;36m";
const std::string BOLD_WHITE   = "\033[1;37m";

void printBanner(const std::string& message, const std::string& color = BOLD_CYAN);
void homeMenu();

#endif // CLI_UI_H