#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdio>

// HARDCODED SECRETS
#define DATABASE_PASSWORD "HardcodedCppPass99#"
#define SYSTEM_ENCRYPTION_KEY "0x4F9A2B81E73C"

void processUserData(const char* input) {
    char buffer[64];
    
    // BUFFER OVERFLOW / UNSAFE MEMORY COPIES
    strcpy(buffer, input); // Dangerous strcpy without length validation
    
    // COMMAND INJECTION
    char command[128];
    sprintf(command, "echo 'User input logged: %s' >> log.txt", input);
    system(command); // Unchecked system command invocation
}

void queryDatabase(const char* username) {
    char sqlQuery[256];
    // SQL INJECTION PATTERN
    sprintf(sqlQuery, "SELECT * FROM accounts WHERE user = '%s';", username);
    std::cout << "Executing Query: " << sqlQuery << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        processUserData(argv[1]);
        queryDatabase(argv[1]);
    }
    
    // WEAK RANDOM NUMBER GENERATOR FOR SECURITY TOKENS
    int token = rand() % 10000;
    std::cout << "Session Security Token: " << token << std::endl;
    
    return 0;
}
