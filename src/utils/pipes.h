#pragma once

#include <Windows.h>
#include <string>
#include <mutex>
#include <queue>


class ServerPipes {
public:
    ServerPipes();
    void init(std::string ipipe_name, std::string opipe_name, std::string ievent_name, std::string oevent_name);
    void start();
    void stop();
    void writeToInput(std::vector<uint8_t> data);
    std::vector<uint8_t> readFromOutput();

    std::string inputPipeName;
    std::string outputPipeName;
    std::string inputEventName;
    std::string outputEventName;

private:
    void create_pipe(std::string pipeName, std::string eventName, bool isInput);
    void input_func(HANDLE hPipe, HANDLE hEvent);
    void output_func(HANDLE hPipe, HANDLE hEvent);
    void set_pipe_security(HANDLE hPipe);
    void create_pipe_security_attr(PSECURITY_ATTRIBUTES psa);
    void unblock_pipes();
    void writetoOutput(uint8_t* data, size_t datalen);

    bool shutdownThreads;
    std::thread inputThread;
    std::thread outputThread;

    std::queue<std::vector<uint8_t>> inputQueue;
    std::mutex inputQueueMtx;
    std::mutex inputMtx;
    std::condition_variable inputCV;

    std::queue<std::vector<uint8_t>> outputQueue;
    std::mutex outputQueueMtx;
    std::mutex outputMtx;
    std::condition_variable outputCV;
};
