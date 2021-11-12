#ifndef PIPE_H
#define PIPE_H

#include "handle.hxx"
#include <vector>
#include <memory>

typedef std::vector<uint8_t> MessageBuffer;

class IMessageExchange{
public:
    IMessageExchange() = default;
    virtual ~IMessageExchange() = default;
    virtual MessageBuffer ReadAll() = 0;
    virtual void WriteAll(const MessageBuffer& data) = 0;
    virtual void WriteAll(const uint8_t* data, uint32_t size) = 0;
};

typedef std::shared_ptr<IMessageExchange> MessageExchangePtr;

class IMessageExchangeFactory{
public:
    IMessageExchangeFactory() = default;
    virtual ~IMessageExchangeFactory() = default;

    virtual MessageExchangePtr Create() = 0;
};

typedef std::shared_ptr<IMessageExchangeFactory> MessageExchangeFactoryPtr;


MessageExchangeFactoryPtr CreatePipeFactory(const std::string& pipeName);


#endif // PIPE_H
