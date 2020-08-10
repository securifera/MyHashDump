#pragma once

#include <vector>
#include <string>

std::vector<std::string> splitStr(const std::string& s, const std::string& d);
bool confirmationPrompt();
void addPrivilegeToCurrentProcess(char* privilegeName);
void addDebugPrivilegesToCurrentProcess();
