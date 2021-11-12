#include "pipe.hxx"
#include <system_error>

class Pipe : public IMessageExchange
{
public:
    Pipe(const std::string& pipePath);

    virtual MessageBuffer ReadAll();
    virtual void WriteAll(const MessageBuffer& data);
    virtual void WriteAll(const uint8_t* data, uint32_t size);

private:
    win32_handle _pipeHandle;
};


class PipeFactory : public IMessageExchangeFactory{

public:
    PipeFactory(const std::string& pipeName) : _pipeName(pipeName){}

    MessageExchangePtr Create(){
        return MessageExchangePtr(new Pipe(_pipeName));
    }

private:
    const std::string _pipeName;

};

Pipe::Pipe(const std::string& pipePath)
{    
    _pipeHandle = win32_handle(INVALID_HANDLE_VALUE);

    while(_pipeHandle.get() == INVALID_HANDLE_VALUE){

        _pipeHandle = win32_handle(CreateFileA(pipePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));

        if(_pipeHandle.get() == INVALID_HANDLE_VALUE){
            if(GetLastError() == ERROR_PIPE_BUSY){
                WaitNamedPipeA(pipePath.c_str(),100);
                continue;
            }else{
                 throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Failed to open pipe");
            }
        }
    }
}

MessageBuffer Pipe::ReadAll(){

    DWORD bytesRead = 0;
    DWORD dataSize = 0;
    MessageBuffer result;

    if(!ReadFile(_pipeHandle.get(), &dataSize, sizeof(dataSize), &bytesRead, nullptr)){
        throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Failed to read data length from pipe");
    }

    if(dataSize > 0){
        result.resize(dataSize);
        uint32_t totalRead = 0;

        while(totalRead < result.size()){
            if(!ReadFile(_pipeHandle.get(), &result[0] + totalRead, result.size() - totalRead, &bytesRead, nullptr)){
                throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Failed to read data from pipe");
            }
            totalRead += bytesRead;
        }
    }

    return result;
}

void Pipe::WriteAll(const MessageBuffer &data){
    WriteAll(data.data(),data.size());
}

void Pipe::WriteAll(const uint8_t * data, uint32_t size){

    DWORD bytesWritten = 0;
    DWORD totalWritten = 0;

    if(!WriteFile(_pipeHandle.get(), &size, sizeof(size), &bytesWritten, nullptr)){
        throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Failed to write message header");
    }

    if(data != nullptr && size > 0){
        while(totalWritten < size){
            if(!WriteFile(_pipeHandle.get(), data + totalWritten, size - totalWritten, &bytesWritten, nullptr)){
                throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Failed to write data to client pipe");
            }
            totalWritten += bytesWritten;
        }
    }
}

MessageExchangeFactoryPtr CreatePipeFactory(const std::string &pipeName){
    return MessageExchangeFactoryPtr(new PipeFactory(pipeName));
}
