#ifndef COMMANDS_H
#define COMMANDS_H

#include "pipe.hxx"
#include <bitsery/bitsery.h>
#include <bitsery/ext/inheritance.h>
#include <bitsery/traits/string.h>
#include <bitsery/adapter/buffer.h>
#include <bitsery/traits/vector.h>

#include <bitsery/brief_syntax.h>
#include <bitsery/brief_syntax/vector.h>
#include <bitsery/brief_syntax/string.h>

using bitsery::ext::BaseClass;
using bitsery::ext::VirtualBaseClass;
using Writer = bitsery::OutputBufferAdapter<MessageBuffer>;
using Reader = bitsery::InputBufferAdapter<MessageBuffer>;

static const int MAX_BUFFER_SIZE = 16384;

enum class CommandType : int{
    Init = 0,
    RelayNTLM,
    NegotiateRequest
};

enum class CommandStatus : uint8_t {
    Ok,
    NoConnection,
    Passive,
    Forward,
    AuthFailed,
    AuthSuccess,
    Replace
};

struct Command{
    public:
        virtual CommandType GetCommandId() const = 0;

        template <typename S>
        void serialize(S& s) {
            s.value1b((uint8_t)GetCommandId());
        }
};


struct CommandResponse{
    public:
        CommandStatus Status;

        CommandResponse() = default;
        CommandResponse(CommandStatus status) : Status(status){}

        template <typename S>
        void serialize(S& s) {
            s.value1b(Status);
        }
};

struct InitCommand : public Command {

    public:
        CommandType GetCommandId() const{
            return CommandType::Init;
        }
};

struct InitCommandResponse : public CommandResponse {
    public:
        uint64_t InitLsaContextOffset;
        uint64_t AcceptLsaContextOffset;
        uint64_t QueryLsaContextOffset;
        uint64_t DeleteLsaContextOffset;
        uint64_t QueryLsaCredOffset;
        uint64_t SpmpLookupPackageOffset;

        InitCommandResponse() = default;
        InitCommandResponse(CommandStatus status) : CommandResponse(status){}

        template <typename S>
        void serialize(S& s) {
            s.ext(*this,BaseClass<CommandResponse>{});
            s.value8b(InitLsaContextOffset);
            s.value8b(AcceptLsaContextOffset);
            s.value8b(QueryLsaContextOffset);
            s.value8b(DeleteLsaContextOffset);
            s.value8b(QueryLsaCredOffset);
            s.value8b(SpmpLookupPackageOffset);
        }
};

struct NtlmRelayCommand : public Command{
    public:
        uint64_t Context;
        uint64_t CredentialHandle;
        uint32_t ProcessID;
        MessageBuffer NTLMMessage;

        NtlmRelayCommand(uint64_t context, uint64_t credHandle, uint32_t pid, const MessageBuffer& ntlmMessage) :
            Context(context), CredentialHandle(credHandle), ProcessID(pid), NTLMMessage(ntlmMessage){}

        CommandType GetCommandId() const{
            return CommandType::RelayNTLM;
        }

        template <typename S>
        void serialize(S& s) {

            if(NTLMMessage.size() > MAX_BUFFER_SIZE)
                throw std::overflow_error("Buffer is too big to serialize");

            s.ext(*this,BaseClass<Command>{});
            s.value8b(Context);
            s.value8b(CredentialHandle);
            s.value4b(ProcessID);
            s.container1b(NTLMMessage, MAX_BUFFER_SIZE);
        }
};

struct NtlmRelayCommandResponse : public CommandResponse {
    public:
        MessageBuffer NTLMMessage;
        NtlmRelayCommandResponse()  = default;
        NtlmRelayCommandResponse(CommandStatus status) : CommandResponse(status){}

        template <typename S>
        void serialize(S& s) {

            if(NTLMMessage.size() > MAX_BUFFER_SIZE)
                throw std::overflow_error("Buffer is too big to serialize");

            s.ext(*this,BaseClass<CommandResponse>{});
            s.container1b(NTLMMessage, MAX_BUFFER_SIZE);
        }
};


struct UserInfo{
    public:
        std::wstring User;
        std::wstring Domain;
        std::wstring UserSid;
        std::vector<std::wstring> Groups;

        UserInfo() = default;

        template <typename S>
        void serialize(S& s) {
            s.text2b(User, 256);
            s.text2b(Domain, 256);
            s.text2b(UserSid, 256);
            s(Groups);
        }
};

struct NtlmRelayCommandFinished : CommandResponse {

    public:
        UserInfo UserInfo;
        std::wstring Workstation;
        NtlmRelayCommandFinished() = default;
        NtlmRelayCommandFinished(CommandStatus status) : CommandResponse(status){}

        template <typename S>
        void serialize(S& s) {
            s.ext(*this,BaseClass<CommandResponse>{});
            s.text2b(Workstation, 256);
            s.object(UserInfo);
        }
};

struct NegotiateCommand : public Command{

public:    
    uint64_t Context;
    uint64_t CredentialHandle;
    uint32_t ProcessID;
    MessageBuffer NegotiateBuffer;

    NegotiateCommand(uint64_t context, uint64_t credHandle, uint32_t pid, const MessageBuffer& negotiateBuffer) :
        Context(context), CredentialHandle(credHandle), ProcessID(pid), NegotiateBuffer(negotiateBuffer){}

    CommandType GetCommandId() const{
        return CommandType::NegotiateRequest;
    }

    template <typename S>
    void serialize(S& s) {

        if(NegotiateBuffer.size() > MAX_BUFFER_SIZE)
            throw std::overflow_error("Buffer is too big to serialize");

        s.ext(*this,BaseClass<Command>{});
        s.value8b(Context);
        s.value8b(CredentialHandle);
        s.value4b(ProcessID);
        s.container1b(NegotiateBuffer, MAX_BUFFER_SIZE);
    }

};

struct NegotiateCommandResponse : public CommandResponse {
    public:
        MessageBuffer NegotiateBuffer;
        NegotiateCommandResponse()  = default;
        NegotiateCommandResponse(CommandStatus status) : CommandResponse(status){}

        template <typename S>
        void serialize(S& s) {

            if(NegotiateBuffer.size() > MAX_BUFFER_SIZE)
                throw std::overflow_error("Buffer is too big to serialize");

            s.ext(*this,BaseClass<CommandResponse>{});
            s.container1b(NegotiateBuffer, MAX_BUFFER_SIZE);
        }
};

template<class T>
T Deserialize(const MessageBuffer& data){
    T result;
    bitsery::ext::InheritanceContext ctx;
    auto status = bitsery::quickDeserialization(ctx, Reader{data.begin(), data.size()}, result);

    if(status.second == false){
        throw std::runtime_error("Failed to deserialize buffer");
    }

    return result;
}

template<class T>
MessageBuffer Serialize(const T& command){
    MessageBuffer data;
    bitsery::ext::InheritanceContext ctx;
    bitsery::quickSerialization(ctx, Writer{data.begin(), data.size()});
    return data;
}


#endif // COMMANDS_H
