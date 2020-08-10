#include <Windows.h> 
#include <stdio.h>
#include <thread>
#include <string>
#include <vector>
#include <iostream>
#include <conio.h>
#include <mutex>

#include "client_pipes.h"
#include "utils.h"
#include "debug.h"

#define BUFSIZE 65535

ClientPipes::ClientPipes()
{
    shutdownThreads = true;
    input_thread = nullptr;
    output_thread = nullptr;
}

void ClientPipes::init(std::string ipipe_name, std::string opipe_name, std::string ievent_name, std::string oevent_name)
{
    inputPipeName = ipipe_name;
    outputPipeName = opipe_name;
    inputEventName = ievent_name;
    outputEventName = oevent_name;

    DbgFprintf(outlogfile, PRINT_INFO1, "ClientPipes::init: %s, %s, %s, %s\n", inputPipeName.c_str(), outputPipeName.c_str(), inputEventName.c_str(), outputEventName.c_str());
}

void ClientPipes::start(std::string ip, bool input, bool output)
{
    shutdownThreads = false;
    if (input) {
        if (inputPipeName.size() == 0 || inputEventName.size() == 0) {
            DbgFprintf(outlogfile, PRINT_ERROR, "Cannot start input pipe, names not specified for all objects\n");
        }
        else {
            DbgFprintf(outlogfile, PRINT_INFO1, "Starting client input pipe, input: %s\n", inputPipeName.c_str());
            input_thread = new std::thread(&ClientPipes::create_pipe, this, ip, inputPipeName, inputEventName, true);
        }
    }

    if (output) {
        if (outputPipeName.size() == 0 || outputEventName.size() == 0) {
            DbgFprintf(outlogfile, PRINT_ERROR, "Cannot start output pipe, names not specified for all objects\n");
        }
        else {
            DbgFprintf(outlogfile, PRINT_INFO1, "Starting client output pipe, input: %s\n", inputPipeName.c_str());
            output_thread = new std::thread(&ClientPipes::create_pipe, this, ip, outputPipeName, outputEventName, false);
        }
    }
}

void ClientPipes::writeToOutput(std::vector<uint8_t> data)
{
    if (data.size() > 0) {
        outputQueueMtx.lock();
        outputQueue.push(data);
        outputQueueMtx.unlock();
        std::unique_lock<std::mutex> lck(outputMtx);
        outputCV.notify_all();
    }
}

std::vector<uint8_t> ClientPipes::readFromInput()
{
    std::unique_lock<std::mutex> lck(inputMtx);
    inputCV.wait_for(lck, std::chrono::milliseconds(500)); //max wait of 5 seconds

    std::vector<uint8_t> data;
    inputQueueMtx.lock();
    if (inputQueue.size() > 0) {
        data = inputQueue.front();
        inputQueue.pop();
    }
    inputQueueMtx.unlock();

    return data;
}

void ClientPipes::stop()
{
    shutdownThreads = true;
    
    if (input_thread != nullptr && input_thread->joinable()) {
        input_thread->join();
        delete input_thread;
        input_thread = nullptr;
    }

    if (output_thread != nullptr && output_thread->joinable()) {
        output_thread->join();
        delete output_thread;
        output_thread = nullptr;
    }
}

void ClientPipes::create_pipe(std::string ip, std::string pipeName, std::string eventName, bool isInput)
{
    if (ip.size() == 0)
        ip = ".";

    HANDLE hPipe = NULL;
    std::string pipename = "\\\\" + ip + "\\pipe\\" + pipeName;

    HANDLE hEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, eventName.c_str());
    if (hEvent == INVALID_HANDLE_VALUE || hEvent == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "OpenEventA failed: 0x%x, %d\n", GetLastError(), GetLastError());
        return;
    }

    DbgFprintf(outlogfile, PRINT_INFO1, "Connecting to pipe: %s, 0x%x\n", pipename.c_str(), hEvent);

    // Try to open a named pipe; wait for it, if necessary. 
    while (!shutdownThreads) {
        hPipe = CreateFileA(pipename.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        // Break if the pipe handle is valid.
        if (hPipe != INVALID_HANDLE_VALUE || hPipe == NULL)
            break;

        // Exit if an error other than ERROR_PIPE_BUSY occurs.
        if (GetLastError() != ERROR_PIPE_BUSY) {
            DbgFprintf(outlogfile, PRINT_ERROR, "Could not open pipe. GLE=%d\n", GetLastError());
            break;
        }

        // All pipe instances are busy, so wait for 20 seconds. 
        if (!WaitNamedPipeA(pipename.c_str(), 20000)) {
            DbgFprintf(outlogfile, PRINT_ERROR, "Could not open pipe: 20 second wait timed out.");
            break;
        }
    }

    if (hPipe != INVALID_HANDLE_VALUE && hEvent != INVALID_HANDLE_VALUE) {

        // The pipe connected; change to message-read mode. 
        DWORD dwMode = PIPE_READMODE_BYTE;// PIPE_READMODE_MESSAGE;
        BOOL ret = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
        if (!ret) {
            DbgFprintf(outlogfile, PRINT_ERROR, "SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
            return;
        }

        if (isInput == true) {
            input_func(hPipe, hEvent);
        }
        else {
            output_func(hPipe, hEvent);
        }

        CloseHandle(hPipe);
        CloseHandle(hEvent);
    }
    else {
        DbgFprintf(outlogfile, PRINT_ERROR, "create_pipe failed. 0x%x, %d. hPipe 0x%llx, hEvent 0x%llx\n", GetLastError(), GetLastError(), hPipe, hEvent);
    }
}

void ClientPipes::input_func(HANDLE hPipe, HANDLE hEvent)
{
    BOOL ret = FALSE;
    DWORD dwRead = 0, bytesRead = 0, bytesAvail = 0, bytesLeft = 0;

    // input validation
    if (hPipe == NULL || hEvent == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "Fatal ClientPipes::input_func. bad input. hPipe: 0x%x, hEvent: 0x%x\n", hPipe, hEvent);
        return;
    }

    // allocate some space to be the local read buffer
    char* buffer = (char*)calloc(BUFSIZE, sizeof(uint8_t));
    if (!buffer) {
        DbgFprintf(outlogfile, PRINT_ERROR, "ClientPipes::input_func calloc error, 0x%x, %d\n", GetLastError(), GetLastError());
        return;
    }

    // continuous loop until pipes are shutdown
    while (!shutdownThreads) {
        // wait for notification event of data in pipe
        DWORD waitResult = WaitForSingleObject(hEvent, 500);
        switch (waitResult) {
        case WAIT_OBJECT_0:
            
            // make sure there is actually data
            ret = PeekNamedPipe(hPipe, NULL, 0, &bytesRead, &bytesAvail, &bytesLeft);
            if (ret == TRUE && bytesAvail > 0) {

                // clear buffer then read data from pipe
                memset(buffer, 0, BUFSIZE);
                ret = ReadFile(hPipe, buffer, BUFSIZE, &dwRead, NULL);
                if (ret == TRUE && dwRead > 0) {

                    // store read data into input queue
                    writetoInput((uint8_t*)buffer, (size_t)dwRead);
                }
            }
            ResetEvent(hEvent);
            break;
        case WAIT_TIMEOUT:
            break;
        default:
            DbgFprintf(outlogfile, PRINT_ERROR, "Wait for event error: 0x%x, %d\n", GetLastError(), GetLastError());
        }
    }
    free(buffer);
}

void ClientPipes::output_func(HANDLE hPipe, HANDLE hEvent)
{
    BOOL ret = FALSE;
    DWORD bytesWritten = 0, bytesRead = 0, bytesAvail = 0, bytesLeft = 0;
    std::unique_lock<std::mutex> lck(outputMtx);

    // input validation
    if (hPipe == NULL || hEvent == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "Fatal ClientPipes::output_func. bad input. hPipe: 0x%x, hEvent: 0x%x\n", hPipe, hEvent);
        return;
    }

    // continuous loop until pipes are shutdown
    while (!shutdownThreads) {

        outputQueueMtx.lock();
        if (outputQueue.size() > 0) {

            // check to see if data in the pipe
            ret = PeekNamedPipe(hPipe, NULL, 0, &bytesRead, &bytesAvail, &bytesLeft);
            if (ret == TRUE && bytesAvail == 0) {

                // pull data from output queue and write to the pipe
                std::vector<uint8_t> buffer = outputQueue.front();
                ret = WriteFile(hPipe, buffer.data(), (DWORD)buffer.size(), &bytesWritten, NULL);
                outputQueue.pop();


                if (buffer.size() != bytesWritten)
                    DbgFprintf(outlogfile, PRINT_ERROR, "ClientPipes: Error not all data written to pipe yet!!!!!!!!!\n");

                // notify event that data is written
                BOOL ret = SetEvent(hEvent);
                if (ret == FALSE) {
                    DbgFprintf(outlogfile, PRINT_ERROR, "ClientPipes::output_pipe error when setting event 0x%x, %d\n", GetLastError(), GetLastError());
                }
            }
        }
        outputQueueMtx.unlock();

        outputCV.wait_for(lck, std::chrono::milliseconds(500)); //max wait of 5 seconds
    }
}

void ClientPipes::writetoInput(uint8_t* data, size_t datalen)
{
    if (data && datalen > 0) {
        // add data block to the input queue and notify conditional variable
        inputQueueMtx.lock();
        inputQueue.push(std::vector<uint8_t>(data, data+datalen));
        inputQueueMtx.unlock();
        std::unique_lock<std::mutex> lck(inputMtx);
        inputCV.notify_all();
    }
}
