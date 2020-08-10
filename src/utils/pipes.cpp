#include "pipes.h"
#include "debug.h"

#include <stdio.h>
#include <string>
#include <mutex>
#include <aclapi.h>


#define BUFSIZE 65535

ServerPipes::ServerPipes()
{
    shutdownThreads = true;
}

void ServerPipes::init(std::string ipipe_name, std::string opipe_name, std::string ievent_name, std::string oevent_name)
{
    inputPipeName = ipipe_name;
    outputPipeName = opipe_name;
    inputEventName = ievent_name;
    outputEventName = oevent_name;

    DbgFprintf(outlogfile, PRINT_INFO1, "ServerPipes::init: %s, %s, %s, %s\n", inputPipeName.c_str(), outputPipeName.c_str(), inputEventName.c_str(), outputEventName.c_str());
}

void ServerPipes::start()
{
    if (inputPipeName.size() == 0 || outputPipeName.size() == 0 || inputEventName.size() == 0 || outputEventName.size() == 0) {
        DbgFprintf(outlogfile, PRINT_ERROR, "Cannot start pipes, names not specified for all objects\n");
        return;
    }

    DbgFprintf(outlogfile, PRINT_INFO1, "Starting server pipes, input: %s, output: %s\n", inputPipeName.c_str(), outputPipeName.c_str());

    shutdownThreads = false;
    inputThread = std::thread(&ServerPipes::create_pipe, this, inputPipeName, inputEventName, true);
    outputThread = std::thread(&ServerPipes::create_pipe, this, outputPipeName, outputEventName, false);
}

void ServerPipes::stop()
{
    shutdownThreads = true;

    unblock_pipes();

    if (inputThread.joinable()) {
        inputThread.join();
    }

    if (outputThread.joinable()) {
        outputThread.join();
    }
}

void ServerPipes::writeToInput(std::vector<uint8_t> data)
{
    inputQueueMtx.lock();
    inputQueue.push(data);
    inputQueueMtx.unlock();
    std::unique_lock<std::mutex> lck(inputMtx);
    inputCV.notify_all();
}

std::vector<uint8_t> ServerPipes::readFromOutput()
{
    std::unique_lock<std::mutex> lck(outputMtx);
    outputCV.wait_for(lck, std::chrono::milliseconds(500)); //max wait of 5 seconds
    std::vector<uint8_t> data;
    outputQueueMtx.lock();
    if (outputQueue.size() > 0) {
        data = outputQueue.front();
        outputQueue.pop();
    }
    outputQueueMtx.unlock();
    return data;
}

void ServerPipes::create_pipe(std::string pipeName, std::string eventName, bool isInput)
{
    BOOL fConnected = FALSE;
    std::string pipepath = "\\\\.\\pipe\\" + pipeName;

    DebugFprintf(outlogfile, PRINT_INFO2, "[+] Creating pipe and event %s, %s\n", pipeName.c_str(), eventName.c_str());

    // set up security descriptor for event
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES saEvent = { 0 };
    saEvent.nLength = sizeof(saEvent);
    saEvent.bInheritHandle = FALSE;
    saEvent.lpSecurityDescriptor = &sd;

    HANDLE hEvent = CreateEventA(&saEvent, TRUE, FALSE, eventName.c_str());
    if (hEvent == INVALID_HANDLE_VALUE || hEvent == NULL) {
        DebugFprintf(outlogfile, PRINT_ERROR, "CreateEventA failed, GLE=%d.\n", GetLastError());
        hEvent = NULL;
        return;
    }

    SECURITY_ATTRIBUTES sa = { 0 };
    create_pipe_security_attr(&sa);
    HANDLE hPipe = CreateNamedPipeA(pipepath.c_str(), PIPE_ACCESS_DUPLEX | WRITE_DAC, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, BUFSIZE, BUFSIZE, 0, &sa);
    if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) {
        DebugFprintf(outlogfile, PRINT_ERROR, "CreateNamedPipe failed, GLE=%d.\n", GetLastError());
        hPipe = NULL;
        return;
    }

    set_pipe_security(hPipe);

    fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (fConnected) {
        DebugFprintf(outlogfile, PRINT_INFO2, "Client connected\n");

        // Create a thread for handling pipe data
        if (isInput) {
            input_func(hPipe, hEvent);
        }
        else {
            output_func(hPipe, hEvent);
        }
    }

    CloseHandle(hPipe);
    CloseHandle(hEvent);
}

void ServerPipes::input_func(HANDLE hPipe, HANDLE hEvent)
{
    BOOL ret = FALSE;
    DWORD bytesWritten = 0,  bytesRead = 0, bytesAvail = 0, bytesLeft = 0;
    std::unique_lock<std::mutex> lck(inputMtx);

    // input validation
    if (hPipe == NULL || hEvent == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "Fatal ServerPipes::input_func. bad input\n");
        return;
    }

    // continuous loop until pipes are shutdown
    while (!shutdownThreads) {

        inputQueueMtx.lock();
        if (inputQueue.size() > 0) {

            // check to make sure pipe is empty
            ret = PeekNamedPipe(hPipe, NULL, 0, &bytesRead, &bytesAvail, &bytesLeft);
            if (ret == TRUE && bytesAvail == 0) {

                // pull data from input queue and write to the pipe
                std::vector<uint8_t> data = inputQueue.front();
                ret = WriteFile(hPipe, data.data(), (DWORD)data.size(), &bytesWritten, NULL);
                inputQueue.pop();

                if (data.size() != bytesWritten)
                    DbgFprintf(outlogfile, PRINT_ERROR, "ServerPipes: Error not all data written to pipe yet!!!!!!!!!\n");

                // notify event that data is written
                BOOL ret = SetEvent(hEvent);
                if (ret == FALSE) {
                    DbgFprintf(outlogfile, PRINT_ERROR, "ClientPipes::output_pipe error when setting event 0x%x, %d\n", GetLastError(), GetLastError());
                }
            }
        }
        inputQueueMtx.unlock();

        inputCV.wait_for(lck, std::chrono::milliseconds(500)); //max wait of 5 seconds
    }
}

void ServerPipes::output_func(HANDLE hPipe, HANDLE hEvent)
{
    BOOL ret = FALSE;
    DWORD dwRead = 0, bytesRead = 0, bytesAvail = 0, bytesLeft = 0;

    // input validation
    if (hPipe == NULL || hEvent == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "Fatal ServerPipes::output_func. bad input\n");
        return;
    }

    // allocate some space to be the local read buffer
    char* readBuf = (char*)calloc(BUFSIZE, sizeof(char));
    if (!readBuf) {
        DbgFprintf(outlogfile, PRINT_ERROR, "Fatal calloc failed ServerPipes::output_func. 0x%x, %d\n", GetLastError(), GetLastError());
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
                memset(readBuf, 0, BUFSIZE);
                ret = ReadFile(hPipe, readBuf, BUFSIZE, &dwRead, NULL);
                if (ret && dwRead > 0) {

                    // store read data into input queue
                    writetoOutput((uint8_t*)readBuf, dwRead);
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
    free(readBuf);
}

void ServerPipes::set_pipe_security(HANDLE hPipe)
{
    if (hPipe != INVALID_HANDLE_VALUE) {
        PACL pOldDACL = NULL;
        if (GetSecurityInfo(hPipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, NULL) == ERROR_SUCCESS) {
            TRUSTEE trustee[1];
            trustee[0].TrusteeForm = TRUSTEE_IS_NAME;
            trustee[0].TrusteeType = TRUSTEE_IS_GROUP;
            trustee[0].ptstrName = (LPCH)"Everyone";
            trustee[0].MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            trustee[0].pMultipleTrustee = NULL;

            EXPLICIT_ACCESS explicit_access_list[1];
            ZeroMemory(&explicit_access_list[0], sizeof(EXPLICIT_ACCESS));

            explicit_access_list[0].grfAccessMode = GRANT_ACCESS;
            explicit_access_list[0].grfAccessPermissions = GENERIC_ALL;
            explicit_access_list[0].grfInheritance = NO_INHERITANCE;
            explicit_access_list[0].Trustee = trustee[0];

            PACL pNewDACL = NULL;
            if (SetEntriesInAcl(1, explicit_access_list, pOldDACL, &pNewDACL) == ERROR_SUCCESS) {
                if (SetSecurityInfo(hPipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL) != ERROR_SUCCESS) {
                    DebugFprintf(outlogfile, PRINT_ERROR, "SetSecurityInfo error: 0x%x, %d\n", GetLastError(), GetLastError());
                }
                //LocalFree(pNewDACL);
            }
            else {
                DebugFprintf(outlogfile, PRINT_ERROR, "SetEntriesInAcl error: 0x%x, %d\n", GetLastError(), GetLastError());
            }
            //LocalFree(pOldDACL);
        }
        else {
            DebugFprintf(outlogfile, PRINT_ERROR, "GetSecurityInfo error: 0x%x, %d\n", GetLastError(), GetLastError());
        }
    }
    else {
        DebugFprintf(outlogfile, PRINT_ERROR, "Invalid handle\n");
    }
}

void ServerPipes::create_pipe_security_attr(PSECURITY_ATTRIBUTES psa)
{
    SID_IDENTIFIER_AUTHORITY sidWorld = SECURITY_WORLD_SID_AUTHORITY;
    PSID sidEveryone = NULL;
    if (!AllocateAndInitializeSid(&sidWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &sidEveryone)) {
        DebugFprintf(outlogfile, PRINT_ERROR, "AllocateAndInitializeSid failed: %u", GetLastError());
        return;
    }

    EXPLICIT_ACCESSW ea = { 0 };
    ea.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)sidEveryone;

    PACL dacl = NULL;
    DWORD result = SetEntriesInAclW(1, &ea, NULL, &dacl);
    if (result != ERROR_SUCCESS) {
        DebugFprintf(outlogfile, PRINT_ERROR, "SetEntriesInAclW failed: %u", result);
    }

    // set up the sacl
    SID_IDENTIFIER_AUTHORITY sidLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID sidLow = NULL;
    if (!AllocateAndInitializeSid(&sidLabel, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &sidLow)) {
        DebugFprintf(outlogfile, PRINT_ERROR, "AllocateAndInitializeSid failed: %u", GetLastError());
    }

    PACL sacl = (PACL)LocalAlloc(LPTR, 256);
    if (!InitializeAcl(sacl, 256, ACL_REVISION_DS)) {
        DebugFprintf(outlogfile, PRINT_ERROR, "InitializeAcl failed: %u", GetLastError());
    }

    if (!AddMandatoryAce(sacl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, sidLow)) {
        DebugFprintf(outlogfile, PRINT_ERROR, "AddMandatoryAce failed: %u", GetLastError());
    }

    // now build the descriptor
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)) {
        DebugFprintf(outlogfile, PRINT_ERROR, "InitializeSecurityDescriptor failed: %u", GetLastError());
    }

    // add the dacl
    if (!SetSecurityDescriptorDacl(sd, TRUE, dacl, FALSE)) {
        DebugFprintf(outlogfile, PRINT_ERROR, "SetSecurityDescriptorDacl failed: %u", GetLastError());
    }

    // now the sacl
    if (!SetSecurityDescriptorSacl(sd, TRUE, sacl, FALSE)) {
        DebugFprintf(outlogfile, PRINT_ERROR, "SetSecurityDescriptorSacl failed: %u", GetLastError());
    }

    psa->nLength = sizeof(SECURITY_ATTRIBUTES);
    psa->bInheritHandle = FALSE;
    psa->lpSecurityDescriptor = sd;
}

void ServerPipes::unblock_pipes()
{
    //force the blocking pipe connection function to continue with a quick connection
    std::string input_pipe_path = "\\\\.\\pipe\\" + inputPipeName;
    HANDLE hPipe = CreateFileA(input_pipe_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    //force the blocking pipe connection function to continue with a quick connection
    std::string output_pipe_path = "\\\\.\\pipe\\" + outputPipeName;
    hPipe = CreateFileA(output_pipe_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
}

void ServerPipes::writetoOutput(uint8_t* data, size_t datalen)
{
    if (data && datalen > 0) {
        // add data block to the input queue and notify conditional variable
        outputQueueMtx.lock();
        outputQueue.push(std::vector<uint8_t>(data, data + datalen));
        outputQueueMtx.unlock();
        std::unique_lock<std::mutex> lck(outputMtx);
        outputCV.notify_all();
    }
}
