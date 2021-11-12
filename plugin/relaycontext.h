#ifndef RELAYCONTEXT_H
#define RELAYCONTEXT_H

#include "pipe.hxx"
#include "commands.h"

class RelayContext
{
public:
    RelayContext(MessageExchangeFactoryPtr& messageExchangeFactory, bool passiveMode, int clientPid);

    NtlmRelayCommandResponse ForwardNegotiateMessage(uint64_t credHandle, const MessageBuffer& ntlmNegotiate);

    NtlmRelayCommandResponse ForwardChallengeMessage(uint64_t credHandle, const MessageBuffer& ntlmChallenge);

    NtlmRelayCommandFinished ForwardAuthenticateMessage(uint64_t credHandle, const MessageBuffer& ntlmAuthenticate);

    NegotiateCommandResponse ForwardNego(uint64_t credHandle, const MessageBuffer& negoToken);

    MessageBuffer SendCommand(const Command& command);

    bool IsPassiveMode() const;

    bool IsAuthenticated() const;

    const UserInfo& GetUserInfo() const;

private:

    bool _passiveMode;
    bool _authSuccess;
    int _clientPid;
    MessageExchangeFactoryPtr _messageExFactory;
    UserInfo _userInfo;
};

#endif // RELAYCONTEXT_H
