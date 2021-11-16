#include "relaycontext.h"


RelayContext::RelayContext(MessageExchangeFactoryPtr &messageExchangeFactory, bool passiveMode, int clientPid) :
    _passiveMode(passiveMode), _authSuccess(false), _clientPid(clientPid), _messageExFactory(messageExchangeFactory){

}

NtlmRelayCommandResponse RelayContext::ForwardNegotiateMessage(uint64_t credHandle, const MessageBuffer &ntlmNegotiate){
    NtlmRelayCommand relayCommand(uint64_t(this), credHandle, _clientPid, ntlmNegotiate);
    auto result = Deserialize<NtlmRelayCommandResponse>(SendCommand(relayCommand));

    if(result.Status == CommandStatus::Forward){
        _passiveMode = false;
    }

    return result;
}

NtlmRelayCommandResponse RelayContext::ForwardChallengeMessage(uint64_t credHandle, const MessageBuffer &ntlmChallenge){
    NtlmRelayCommand relayCommand(uint64_t(this), credHandle, _clientPid, ntlmChallenge);
    return Deserialize<NtlmRelayCommandResponse>(SendCommand(relayCommand));
}

NtlmRelayCommandFinished RelayContext::ForwardAuthenticateMessage(uint64_t credHandle, const MessageBuffer& ntlmAuthenticate){
    NtlmRelayCommand relayCommand(uint64_t(this), credHandle, _clientPid, ntlmAuthenticate);
    auto result = Deserialize<NtlmRelayCommandFinished>(SendCommand(relayCommand));
    _authSuccess = result.Status == CommandStatus::AuthSuccess;
    _userInfo = result.UserInfo;
    return result;
}

NegotiateCommandResponse RelayContext::ForwardNego(uint64_t credHandle, const MessageBuffer &negoToken){
    NegotiateCommand negoCommand(uint64_t(this), credHandle, _clientPid, negoToken);
    auto result = Deserialize<NegotiateCommandResponse>(SendCommand(negoCommand));
    return result;
}

bool RelayContext::IsPassiveMode() const{
    return _passiveMode;
}

bool RelayContext::IsAuthenticated() const{
    return _authSuccess;
}

const UserInfo &RelayContext::GetUserInfo() const{
    return _userInfo;
}

MessageBuffer RelayContext::SendCommand(const Command& command){

    MessageExchangePtr messageEx =  _messageExFactory->Create();
    bitsery::ext::InheritanceContext ctx;
    MessageBuffer buffer;
    size_t writtenSize = 0;

    if(command.GetCommandId() == CommandType::RelayNTLM){
        const NtlmRelayCommand& relayCommand = (const NtlmRelayCommand&)(command);
        writtenSize = bitsery::quickSerialization(ctx, Writer{buffer}, relayCommand);
    }else if(command.GetCommandId() == CommandType::NegotiateRequest){
        const NegotiateCommand& negCommand = (const NegotiateCommand&)(command);
        writtenSize = bitsery::quickSerialization(ctx, Writer{buffer}, negCommand);
    }else{
        writtenSize = bitsery::quickSerialization(ctx, Writer{buffer}, command);
    }

    messageEx->WriteAll(buffer.data(), writtenSize);
    return messageEx->ReadAll();
}
