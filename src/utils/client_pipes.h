#pragma once

#include <string>
#include <thread>
#include <mutex>
#include <queue>


class ClientPipes {
public:
	ClientPipes();
	void init(std::string ipipe_name, std::string opipe_name, std::string ievent_name, std::string oevent_name);
	void start(std::string ip, bool input, bool output);
	void stop();
	void writeToOutput(std::vector<uint8_t> data);
	std::vector<uint8_t> readFromInput();

private:
	void create_pipe(std::string ip, std::string pipeName, std::string eventName, bool isInput);
	void input_func(HANDLE hPipe, HANDLE hEvent);
	void output_func(HANDLE hPipe, HANDLE hEvent);

	void writetoInput(uint8_t* data, size_t datalen);

	bool shutdownThreads;

	std::thread* input_thread;
	std::thread* output_thread;

	std::queue<std::vector<uint8_t>> inputQueue;
	std::mutex inputQueueMtx;
	std::mutex inputMtx;
	std::condition_variable inputCV;

	std::queue<std::vector<uint8_t>> outputQueue;
	std::mutex outputQueueMtx;
	std::mutex outputMtx;
	std::condition_variable outputCV;

	std::string inputPipeName;
	std::string outputPipeName;
	std::string inputEventName;
	std::string outputEventName;
};
