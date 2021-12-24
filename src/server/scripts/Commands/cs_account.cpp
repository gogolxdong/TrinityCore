/*
 * This file is part of the TrinityCore Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* ScriptData
Name: account_commandscript
%Complete: 100
Comment: All account related commands
Category: commandscripts
EndScriptData */

#include "AccountMgr.h"
#include "AES.h"
#include "Base32.h"
#include "Chat.h"
#include "CryptoGenerics.h"
#include "CryptoRandom.h"
#include "DatabaseEnv.h"
#include "IpAddress.h"
#include "IPLocation.h"
#include "Language.h"
#include "Log.h"
#include "Player.h"
#include "ScriptMgr.h"
#include "SecretMgr.h"
#include "TOTP.h"
#include "World.h"
#include "WorldSession.h"
#include <unordered_map>
#include <memory>
#include <thread>
#include <atomic>
#include <WorldSocket.h>
using namespace Trinity::ChatCommands;

class account_commandscript : public CommandScript
{
public:
    account_commandscript() : CommandScript("account_commandscript") {}

    ChatCommandTable GetCommands() const override
    {
        static ChatCommandTable accountSetCommandTable =
            {
                {"addon", HandleAccountSetAddonCommand, LANG_COMMAND_ACC_SET_ADDON_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_SET_ADDON, Console::Yes},
                {"sec regmail", HandleAccountSetRegEmailCommand, LANG_COMMAND_ACC_SET_SEC_REGMAIL_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_SET_SEC_REGMAIL, Console::Yes},
                {"sec email", HandleAccountSetEmailCommand, LANG_COMMAND_ACC_SET_SEC_EMAIL_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_SET_SEC_EMAIL, Console::Yes},
                {"gmlevel", HandleAccountSetSecLevelCommand, LANG_COMMAND_ACC_SET_SECLEVEL_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_SET_SECLEVEL, Console::Yes}, // temp for a transition period
                {"seclevel", HandleAccountSetSecLevelCommand, LANG_COMMAND_ACC_SET_SECLEVEL_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_SET_SECLEVEL, Console::Yes},
                {"password", HandleAccountSetPasswordCommand, LANG_COMMAND_ACC_SET_PASSWORD_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_SET_PASSWORD, Console::Yes},
                {"2fa", HandleAccountSet2FACommand, LANG_COMMAND_ACC_SET_2FA_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_SET_2FA, Console::Yes},
            };
        static ChatCommandTable accountOnlinelistCommandTable =
            {
                {"", HandleAccountOnlineListCommand, LANG_COMMAND_ACC_ONLINELIST_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_ONLINE_LIST, Console::Yes},
                {"ip", HandleAccountOnlineListWithIpFilterCommand, LANG_COMMAND_ACC_ONLINELIST_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_ONLINE_LIST, Console::Yes},
                {"limit", HandleAccountOnlineListWithLimitCommand, LANG_COMMAND_ACC_ONLINELIST_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_ONLINE_LIST, Console::Yes},
                {"map", HandleAccountOnlineListWithMapFilterCommand, LANG_COMMAND_ACC_ONLINELIST_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_ONLINE_LIST, Console::Yes},
                {"zone", HandleAccountOnlineListWithZoneFilterCommand, LANG_COMMAND_ACC_ONLINELIST_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_ONLINE_LIST, Console::Yes},
            };
        static ChatCommandTable accountCommandTable =
            {
                {"2fa setup", HandleAccount2FASetupCommand, LANG_COMMAND_ACC_2FA_SETUP_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_2FA_SETUP, Console::No},
                {"2fa remove", HandleAccount2FARemoveCommand, LANG_COMMAND_ACC_2FA_REMOVE_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_2FA_REMOVE, Console::No},
                {"addon", HandleAccountAddonCommand, LANG_COMMAND_ACC_ADDON_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_ADDON, Console::No},
                {"create", HandleAccountCreateCommand, LANG_COMMAND_ACC_CREATE_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_CREATE, Console::Yes},
                {"delete", HandleAccountDeleteCommand, LANG_COMMAND_ACC_DELETE_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_DELETE, Console::Yes},
                {"email", HandleAccountEmailCommand, LANG_COMMAND_ACC_EMAIL_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_EMAIL, Console::No},
                {"onlinelist", accountOnlinelistCommandTable},
                {"lock country", HandleAccountLockCountryCommand, LANG_COMMAND_ACC_LOCK_COUNTRY_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_LOCK_COUNTRY, Console::No},
                {"lock ip", HandleAccountLockIpCommand, LANG_COMMAND_ACC_LOCK_IP_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_LOCK_IP, Console::No},
                {"set", accountSetCommandTable},
                {"password", HandleAccountPasswordCommand, LANG_COMMAND_ACC_PASSWORD_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT_PASSWORD, Console::No},
                {"", HandleAccountCommand, LANG_COMMAND_ACCOUNT_HELP, rbac::RBAC_PERM_COMMAND_ACCOUNT, Console::No},
            };
        static ChatCommandTable commandTable =
            {
                {"account", accountCommandTable},
            };
        return commandTable;
    }

    static bool HandleAccount2FASetupCommand(ChatHandler *handler, Optional<uint32> token)
    {
        auto const &masterKey = sSecretMgr->GetSecret(SECRET_TOTP_MASTER_KEY);
        if (!masterKey.IsAvailable())
        {
            handler->SendSysMessage(LANG_2FA_COMMANDS_NOT_SETUP);
            handler->SetSentErrorMessage(true);
            return false;
        }

        uint32 const accountId = handler->GetSession()->GetAccountId();

        { // check if 2FA already enabled
            LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_ACCOUNT_TOTP_SECRET);
            stmt->setUInt32(0, accountId);
            PreparedQueryResult result = LoginDatabase.Query(stmt);

            if (!result)
            {
                TC_LOG_ERROR("misc", "Account %u not found in login database when processing .account 2fa setup command.", accountId);
                handler->SendSysMessage(LANG_UNKNOWN_ERROR);
                handler->SetSentErrorMessage(true);
                return false;
            }

            if (!result->Fetch()->IsNull())
            {
                handler->SendSysMessage(LANG_2FA_ALREADY_SETUP);
                handler->SetSentErrorMessage(true);
                return false;
            }
        }

        // store random suggested secrets
        static std::unordered_map<uint32, Trinity::Crypto::TOTP::Secret> suggestions;
        auto pair = suggestions.emplace(std::piecewise_construct, std::make_tuple(accountId), std::make_tuple(Trinity::Crypto::TOTP::RECOMMENDED_SECRET_LENGTH)); // std::vector 1-argument size_t constructor invokes resize
        if (pair.second)                                                                                                                                          // no suggestion yet, generate random secret
            Trinity::Crypto::GetRandomBytes(pair.first->second);

        if (!pair.second && token) // suggestion already existed and token specified - validate
        {
            if (Trinity::Crypto::TOTP::ValidateToken(pair.first->second, *token))
            {
                if (masterKey)
                    Trinity::Crypto::AEEncryptWithRandomIV<Trinity::Crypto::AES>(pair.first->second, *masterKey);

                LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_ACCOUNT_TOTP_SECRET);
                stmt->setBinary(0, pair.first->second);
                stmt->setUInt32(1, accountId);
                LoginDatabase.Execute(stmt);
                suggestions.erase(pair.first);
                handler->SendSysMessage(LANG_2FA_SETUP_COMPLETE);
                return true;
            }
            else
                handler->SendSysMessage(LANG_2FA_INVALID_TOKEN);
        }

        // new suggestion, or no token specified, output TOTP parameters
        handler->PSendSysMessage(LANG_2FA_SECRET_SUGGESTION, Trinity::Encoding::Base32::Encode(pair.first->second));
        handler->SetSentErrorMessage(true);
        return false;
    }

    static bool HandleAccount2FARemoveCommand(ChatHandler *handler, Optional<uint32> token)
    {
        auto const &masterKey = sSecretMgr->GetSecret(SECRET_TOTP_MASTER_KEY);
        if (!masterKey.IsAvailable())
        {
            handler->SendSysMessage(LANG_2FA_COMMANDS_NOT_SETUP);
            handler->SetSentErrorMessage(true);
            return false;
        }

        uint32 const accountId = handler->GetSession()->GetAccountId();
        Trinity::Crypto::TOTP::Secret secret;
        { // get current TOTP secret
            LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_ACCOUNT_TOTP_SECRET);
            stmt->setUInt32(0, accountId);
            PreparedQueryResult result = LoginDatabase.Query(stmt);

            if (!result)
            {
                TC_LOG_ERROR("misc", "Account %u not found in login database when processing .account 2fa setup command.", accountId);
                handler->SendSysMessage(LANG_UNKNOWN_ERROR);
                handler->SetSentErrorMessage(true);
                return false;
            }

            Field *field = result->Fetch();
            if (field->IsNull())
            { // 2FA not enabled
                handler->SendSysMessage(LANG_2FA_NOT_SETUP);
                handler->SetSentErrorMessage(true);
                return false;
            }

            secret = field->GetBinary();
        }

        if (token)
        {
            if (masterKey)
            {
                bool success = Trinity::Crypto::AEDecrypt<Trinity::Crypto::AES>(secret, *masterKey);
                if (!success)
                {
                    TC_LOG_ERROR("misc", "Account %u has invalid ciphertext in TOTP token.", accountId);
                    handler->SendSysMessage(LANG_UNKNOWN_ERROR);
                    handler->SetSentErrorMessage(true);
                    return false;
                }
            }

            if (Trinity::Crypto::TOTP::ValidateToken(secret, *token))
            {
                LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_ACCOUNT_TOTP_SECRET);
                stmt->setNull(0);
                stmt->setUInt32(1, accountId);
                LoginDatabase.Execute(stmt);
                handler->SendSysMessage(LANG_2FA_REMOVE_COMPLETE);
                return true;
            }
            else
                handler->SendSysMessage(LANG_2FA_INVALID_TOKEN);
        }

        handler->SendSysMessage(LANG_2FA_REMOVE_NEED_TOKEN);
        handler->SetSentErrorMessage(true);
        return false;
    }

    static bool HandleAccountAddonCommand(ChatHandler *handler, uint8 expansion)
    {
        if (expansion > sWorld->getIntConfig(CONFIG_EXPANSION))
        {
            handler->SendSysMessage(LANG_IMPROPER_VALUE);
            handler->SetSentErrorMessage(true);
            return false;
        }

        LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_EXPANSION);

        stmt->setUInt8(0, expansion);
        stmt->setUInt32(1, handler->GetSession()->GetAccountId());

        LoginDatabase.Execute(stmt);

        handler->PSendSysMessage(LANG_ACCOUNT_ADDON, expansion);
        return true;
    }

    /// Create an account
    static bool HandleAccountCreateCommand(ChatHandler *handler, std::string const &accountName, std::string const &password, Optional<std::string> const &email)
    {
        if (accountName.find('@') != std::string::npos)
        {
            handler->PSendSysMessage(LANG_ACCOUNT_USE_BNET_COMMANDS);
            handler->SetSentErrorMessage(true);
            return false;
        }

        switch (sAccountMgr->CreateAccount(accountName, password, email.value_or("")))
        {
        case AccountOpResult::AOR_OK:
            handler->PSendSysMessage(LANG_ACCOUNT_CREATED, accountName);
            if (handler->GetSession())
            {
                TC_LOG_INFO("entities.player.character", "Account: %d (IP: %s) Character:[%s] %s) created Account %s (Email: '%s')",
                            handler->GetSession()->GetAccountId(), handler->GetSession()->GetRemoteAddress().c_str(),
                            handler->GetSession()->GetPlayer()->GetName().c_str(), handler->GetSession()->GetPlayer()->GetGUID().ToString().c_str(),
                            accountName.c_str(), email.value_or("").c_str());
            }
            break;
        case AccountOpResult::AOR_NAME_TOO_LONG:
            handler->SendSysMessage(LANG_ACCOUNT_NAME_TOO_LONG);
            handler->SetSentErrorMessage(true);
            return false;
        case AccountOpResult::AOR_PASS_TOO_LONG:
            handler->SendSysMessage(LANG_ACCOUNT_PASS_TOO_LONG);
            handler->SetSentErrorMessage(true);
            return false;
        case AccountOpResult::AOR_NAME_ALREADY_EXIST:
            handler->SendSysMessage(LANG_ACCOUNT_ALREADY_EXIST);
            handler->SetSentErrorMessage(true);
            return false;
        case AccountOpResult::AOR_DB_INTERNAL_ERROR:
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_CREATED_SQL_ERROR, accountName);
            handler->SetSentErrorMessage(true);
            return false;
        default:
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_CREATED, accountName);
            handler->SetSentErrorMessage(true);
            return false;
        }

        return true;
    }

    /// Delete a user account and all associated characters in this realm
    /// @todo This function has to be enhanced to respect the login/realm split (delete char, delete account chars in realm then delete account)
    static bool HandleAccountDeleteCommand(ChatHandler *handler, std::string accountName)
    {
        if (!Utf8ToUpperOnlyLatin(accountName))
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        uint32 accountId = AccountMgr::GetId(accountName);
        if (!accountId)
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        /// Commands not recommended call from chat, but support anyway
        /// can delete only for account with less security
        /// This is also reject self apply in fact
        if (handler->HasLowerSecurityAccount(nullptr, accountId, true))
            return false;

        AccountOpResult result = AccountMgr::DeleteAccount(accountId);
        switch (result)
        {
        case AccountOpResult::AOR_OK:
            handler->PSendSysMessage(LANG_ACCOUNT_DELETED, accountName.c_str());
            break;
        case AccountOpResult::AOR_NAME_NOT_EXIST:
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        case AccountOpResult::AOR_DB_INTERNAL_ERROR:
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_DELETED_SQL_ERROR, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        default:
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_DELETED, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        return true;
    }

    /// Display info on users currently in the realm
    static bool HandleAccountOnlineListCommand(ChatHandler *handler)
    {
        return HandleAccountOnlineListCommandWithParameters(handler, {}, {}, {}, {});
    }

    static bool HandleAccountOnlineListWithIpFilterCommand(ChatHandler *handler, std::string ipAddress)
    {
        return HandleAccountOnlineListCommandWithParameters(handler, ipAddress, {}, {}, {});
    }

    static bool HandleAccountOnlineListWithLimitCommand(ChatHandler *handler, uint32 limit)
    {
        return HandleAccountOnlineListCommandWithParameters(handler, {}, limit, {}, {});
    }

    static bool HandleAccountOnlineListWithMapFilterCommand(ChatHandler *handler, uint32 mapId)
    {
        return HandleAccountOnlineListCommandWithParameters(handler, {}, {}, mapId, {});
    }

    static bool HandleAccountOnlineListWithZoneFilterCommand(ChatHandler *handler, uint32 zoneId)
    {
        return HandleAccountOnlineListCommandWithParameters(handler, {}, {}, {}, zoneId);
    }

    static bool HandleAccountOnlineListCommandWithParameters(ChatHandler *handler, Optional<std::string> ipAddress, Optional<uint32> limit, Optional<uint32> mapId, Optional<uint32> zoneId)
    {
        size_t sessionsMatchCount = 0;

        SessionMap const &sessionsMap = sWorld->GetAllSessions();
        for (SessionMap::value_type const &sessionPair : sessionsMap)
        {
            WorldSession *session = sessionPair.second;
            Player *player = session->GetPlayer();

            // Ignore sessions on character selection screen
            if (!player)
                continue;

            uint32 playerMapId = player->GetMapId();
            uint32 playerZoneId = player->GetZoneId();

            // Apply optional ipAddress filter
            if (ipAddress && ipAddress != session->GetRemoteAddress())
                continue;

            // Apply optional mapId filter
            if (mapId && mapId != playerMapId)
                continue;

            // Apply optional zoneId filter
            if (zoneId && zoneId != playerZoneId)
                continue;

            if (!sessionsMatchCount)
            {
                ///- Display the list of account/characters online on the first matched sessions
                handler->SendSysMessage(LANG_ACCOUNT_LIST_BAR_HEADER);
                handler->SendSysMessage(LANG_ACCOUNT_LIST_HEADER);
                handler->SendSysMessage(LANG_ACCOUNT_LIST_BAR);
            }

            handler->PSendSysMessage(LANG_ACCOUNT_LIST_LINE,
                                     session->GetAccountName().c_str(),
                                     session->GetPlayerName().c_str(),
                                     session->GetRemoteAddress().c_str(),
                                     playerMapId,
                                     playerZoneId,
                                     session->Expansion(),
                                     int32(session->GetSecurity()));

            ++sessionsMatchCount;

            // Apply optional count limit
            if (limit && sessionsMatchCount >= limit)
                break;
        }

        // Header is printed on first matched session. If it wasn't printed then no sessions matched the criteria
        if (!sessionsMatchCount)
        {
            handler->SendSysMessage(LANG_ACCOUNT_LIST_EMPTY);
            return true;
        }

        handler->SendSysMessage(LANG_ACCOUNT_LIST_BAR);
        return true;
    }

    static bool HandleAccountLockCountryCommand(ChatHandler *handler, bool state)
    {
        if (state)
        {
            if (IpLocationRecord const *location = sIPLocation->GetLocationRecord(handler->GetSession()->GetRemoteAddress()))
            {
                LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_ACCOUNT_LOCK_COUNTRY);
                stmt->setString(0, location->CountryCode);
                stmt->setUInt32(1, handler->GetSession()->GetAccountId());
                LoginDatabase.Execute(stmt);
                handler->PSendSysMessage(LANG_COMMAND_ACCLOCKLOCKED);
            }
            else
            {
                handler->PSendSysMessage("No IP2Location information - account not locked");
                handler->SetSentErrorMessage(true);
                return false;
            }
        }
        else
        {
            LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_ACCOUNT_LOCK_COUNTRY);
            stmt->setString(0, "00");
            stmt->setUInt32(1, handler->GetSession()->GetAccountId());
            LoginDatabase.Execute(stmt);
            handler->PSendSysMessage(LANG_COMMAND_ACCLOCKUNLOCKED);
        }
        return true;
    }

    static bool HandleAccountLockIpCommand(ChatHandler *handler, bool state)
    {
        LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_ACCOUNT_LOCK);

        if (state)
        {
            stmt->setBool(0, true); // locked
            handler->PSendSysMessage(LANG_COMMAND_ACCLOCKLOCKED);
        }
        else
        {
            stmt->setBool(0, false); // unlocked
            handler->PSendSysMessage(LANG_COMMAND_ACCLOCKUNLOCKED);
        }

        stmt->setUInt32(1, handler->GetSession()->GetAccountId());

        LoginDatabase.Execute(stmt);
        return true;
    }

    static bool HandleAccountEmailCommand(ChatHandler *handler, std::string const &oldEmail, std::string const &password, std::string const &email, std::string const &emailConfirm)
    {
        if (!AccountMgr::CheckEmail(handler->GetSession()->GetAccountId(), oldEmail))
        {
            handler->SendSysMessage(LANG_COMMAND_WRONGEMAIL);
            sScriptMgr->OnFailedEmailChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            TC_LOG_INFO("entities.player.character", "Account: %u (IP: %s) Character:[%s] %s Tried to change email, but the provided email [%s] is not equal to registration email [%s].",
                        handler->GetSession()->GetAccountId(), handler->GetSession()->GetRemoteAddress().c_str(),
                        handler->GetSession()->GetPlayer()->GetName().c_str(), handler->GetSession()->GetPlayer()->GetGUID().ToString().c_str(),
                        email.c_str(), oldEmail.c_str());
            return false;
        }

        if (!AccountMgr::CheckPassword(handler->GetSession()->GetAccountId(), password))
        {
            handler->SendSysMessage(LANG_COMMAND_WRONGOLDPASSWORD);
            sScriptMgr->OnFailedEmailChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            TC_LOG_INFO("entities.player.character", "Account: %u (IP: %s) Character:[%s] %s Tried to change email, but the provided password is wrong.",
                        handler->GetSession()->GetAccountId(), handler->GetSession()->GetRemoteAddress().c_str(),
                        handler->GetSession()->GetPlayer()->GetName().c_str(), handler->GetSession()->GetPlayer()->GetGUID().ToString().c_str());
            return false;
        }

        if (email == oldEmail)
        {
            handler->SendSysMessage(LANG_OLD_EMAIL_IS_NEW_EMAIL);
            sScriptMgr->OnFailedEmailChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            return false;
        }

        if (email != emailConfirm)
        {
            handler->SendSysMessage(LANG_NEW_EMAILS_NOT_MATCH);
            sScriptMgr->OnFailedEmailChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            TC_LOG_INFO("entities.player.character", "Account: %u (IP: %s) Character:[%s] %s Tried to change email, but the confirm email does not match.",
                        handler->GetSession()->GetAccountId(), handler->GetSession()->GetRemoteAddress().c_str(),
                        handler->GetSession()->GetPlayer()->GetName().c_str(), handler->GetSession()->GetPlayer()->GetGUID().ToString().c_str());
            return false;
        }

        AccountOpResult result = AccountMgr::ChangeEmail(handler->GetSession()->GetAccountId(), email);
        switch (result)
        {
        case AccountOpResult::AOR_OK:
            handler->SendSysMessage(LANG_COMMAND_EMAIL);
            sScriptMgr->OnEmailChange(handler->GetSession()->GetAccountId());
            TC_LOG_INFO("entities.player.character", "Account: %u (IP: %s) Character:[%s] %s Changed Email from [%s] to [%s].",
                        handler->GetSession()->GetAccountId(), handler->GetSession()->GetRemoteAddress().c_str(),
                        handler->GetSession()->GetPlayer()->GetName().c_str(), handler->GetSession()->GetPlayer()->GetGUID().ToString().c_str(),
                        oldEmail.c_str(), email.c_str());
            break;
        case AccountOpResult::AOR_EMAIL_TOO_LONG:
            handler->SendSysMessage(LANG_EMAIL_TOO_LONG);
            sScriptMgr->OnFailedEmailChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            return false;
        default:
            handler->SendSysMessage(LANG_COMMAND_NOTCHANGEEMAIL);
            handler->SetSentErrorMessage(true);
            return false;
        }

        return true;
    }

    static bool HandleAccountPasswordCommand(ChatHandler *handler, std::string const &oldPassword, std::string const &newPassword, std::string const &confirmPassword, Optional<std::string> const &confirmEmail)
    {
        // First, we check config. What security type (sec type) is it ? Depending on it, the command branches out
        uint32 const pwConfig = sWorld->getIntConfig(CONFIG_ACC_PASSCHANGESEC); // 0 - PW_NONE, 1 - PW_EMAIL, 2 - PW_RBAC

        // We compare the old, saved password to the entered old password - no chance for the unauthorized.
        if (!AccountMgr::CheckPassword(handler->GetSession()->GetAccountId(), oldPassword))
        {
            handler->SendSysMessage(LANG_COMMAND_WRONGOLDPASSWORD);
            sScriptMgr->OnFailedPasswordChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            TC_LOG_INFO("entities.player.character", "Account: %u (IP: %s) Character:[%s] %s Tried to change password, but the provided old password is wrong.",
                        handler->GetSession()->GetAccountId(), handler->GetSession()->GetRemoteAddress().c_str(),
                        handler->GetSession()->GetPlayer()->GetName().c_str(), handler->GetSession()->GetPlayer()->GetGUID().ToString().c_str());
            return false;
        }

        // This compares the old, current email to the entered email - however, only...
        if ((pwConfig == PW_EMAIL || (pwConfig == PW_RBAC && handler->HasPermission(rbac::RBAC_PERM_EMAIL_CONFIRM_FOR_PASS_CHANGE))) // ...if either PW_EMAIL or PW_RBAC with the Permission is active...
            && !AccountMgr::CheckEmail(handler->GetSession()->GetAccountId(), confirmEmail.value_or("")))                            // ... and returns false if the comparison fails.
        {
            handler->SendSysMessage(LANG_COMMAND_WRONGEMAIL);
            sScriptMgr->OnFailedPasswordChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            TC_LOG_INFO("entities.player.character", "Account: %u (IP: %s) Character:[%s] %s Tried to change password, but the entered email [%s] is wrong.",
                        handler->GetSession()->GetAccountId(), handler->GetSession()->GetRemoteAddress().c_str(),
                        handler->GetSession()->GetPlayer()->GetName().c_str(), handler->GetSession()->GetPlayer()->GetGUID().ToString().c_str(),
                        confirmEmail.value_or("").c_str());
            return false;
        }

        // Making sure that newly entered password is correctly entered.
        if (newPassword != confirmPassword)
        {
            handler->SendSysMessage(LANG_NEW_PASSWORDS_NOT_MATCH);
            sScriptMgr->OnFailedPasswordChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            return false;
        }

        // Changes password and prints result.
        AccountOpResult result = AccountMgr::ChangePassword(handler->GetSession()->GetAccountId(), newPassword);
        switch (result)
        {
        case AccountOpResult::AOR_OK:
            handler->SendSysMessage(LANG_COMMAND_PASSWORD);
            sScriptMgr->OnPasswordChange(handler->GetSession()->GetAccountId());
            TC_LOG_INFO("entities.player.character", "Account: %u (IP: %s) Character:[%s] %s changed password.",
                        handler->GetSession()->GetAccountId(), handler->GetSession()->GetRemoteAddress().c_str(),
                        handler->GetSession()->GetPlayer()->GetName().c_str(), handler->GetSession()->GetPlayer()->GetGUID().ToString().c_str());
            break;
        case AccountOpResult::AOR_PASS_TOO_LONG:
            handler->SendSysMessage(LANG_PASSWORD_TOO_LONG);
            sScriptMgr->OnFailedPasswordChange(handler->GetSession()->GetAccountId());
            handler->SetSentErrorMessage(true);
            return false;
        default:
            handler->SendSysMessage(LANG_COMMAND_NOTCHANGEPASSWORD);
            handler->SetSentErrorMessage(true);
            return false;
        }

        return true;
    }

    static bool HandleAccountCommand(ChatHandler *handler)
    {
        // GM Level
        AccountTypes securityLevel = handler->GetSession()->GetSecurity();
        handler->PSendSysMessage(LANG_ACCOUNT_LEVEL, uint32(securityLevel));

        // Security level required
        bool hasRBAC = (handler->HasPermission(rbac::RBAC_PERM_EMAIL_CONFIRM_FOR_PASS_CHANGE) ? true : false);
        uint32 pwConfig = sWorld->getIntConfig(CONFIG_ACC_PASSCHANGESEC); // 0 - PW_NONE, 1 - PW_EMAIL, 2 - PW_RBAC

        handler->PSendSysMessage(LANG_ACCOUNT_SEC_TYPE, (pwConfig == PW_NONE ? "Lowest level: No Email input required." : pwConfig == PW_EMAIL ? "Highest level: Email input required."
                                                                                                                      : pwConfig == PW_RBAC    ? "Special level: Your account may require email input depending on settings. That is the case if another line is printed."
                                                                                                                                               : "Unknown security level: Config error?"));

        // RBAC required display - is not displayed for console
        if (pwConfig == PW_RBAC && handler->GetSession() && hasRBAC)
            handler->PSendSysMessage(LANG_RBAC_EMAIL_REQUIRED);

        // Email display if sufficient rights
        if (handler->HasPermission(rbac::RBAC_PERM_MAY_CHECK_OWN_EMAIL))
        {
            std::string emailoutput;
            uint32 accountId = handler->GetSession()->GetAccountId();

            LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_GET_EMAIL_BY_ID);
            stmt->setUInt32(0, accountId);
            PreparedQueryResult result = LoginDatabase.Query(stmt);

            if (result)
            {
                emailoutput = (*result)[0].GetString();
                handler->PSendSysMessage(LANG_COMMAND_EMAIL_OUTPUT, emailoutput.c_str());
            }
        }

        return true;
    }

    /// Set/Unset the expansion level for an account
    static bool HandleAccountSetAddonCommand(ChatHandler *handler, Optional<std::string> accountName, uint8 expansion)
    {
        uint32 accountId;
        if (accountName)
        {
            ///- Convert Account name to Upper Format
            if (!Utf8ToUpperOnlyLatin(*accountName))
            {
                handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName->c_str());
                handler->SetSentErrorMessage(true);
                return false;
            }

            accountId = AccountMgr::GetId(*accountName);
            if (!accountId)
            {
                handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName->c_str());
                handler->SetSentErrorMessage(true);
                return false;
            }
        }
        else
        {
            Player *player = handler->getSelectedPlayer();
            if (!player)
                return false;

            accountId = player->GetSession()->GetAccountId();
            accountName.emplace();
            AccountMgr::GetName(accountId, *accountName);
        }

        // Let set addon state only for lesser (strong) security level
        // or to self account
        if (handler->GetSession() && handler->GetSession()->GetAccountId() != accountId &&
            handler->HasLowerSecurityAccount(nullptr, accountId, true))
            return false;

        if (expansion > sWorld->getIntConfig(CONFIG_EXPANSION))
            return false;

        LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_EXPANSION);

        stmt->setUInt8(0, expansion);
        stmt->setUInt32(1, accountId);

        LoginDatabase.Execute(stmt);

        handler->PSendSysMessage(LANG_ACCOUNT_SETADDON, accountName->c_str(), accountId, expansion);
        return true;
    }

    static bool HandleAccountSetSecLevelCommand(ChatHandler *handler, Optional<std::string> accountName, uint8 securityLevel, Optional<int32> realmId)
    {
        uint32 accountId;
        if (accountName)
        {
            if (!Utf8ToUpperOnlyLatin(*accountName))
            {
                handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName->c_str());
                handler->SetSentErrorMessage(true);
                return false;
            }

            accountId = AccountMgr::GetId(*accountName);
            if (!accountId)
            {
                handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName->c_str());
                handler->SetSentErrorMessage(true);
                return false;
            }
        }
        else
        {
            Player *player = handler->getSelectedPlayer();
            if (!player)
                return false;
            accountId = player->GetSession()->GetAccountId();
            accountName.emplace();
            AccountMgr::GetName(accountId, *accountName);
        }

        if (securityLevel >= SEC_CONSOLE)
        {
            handler->SendSysMessage(LANG_BAD_VALUE);
            handler->SetSentErrorMessage(true);
            return false;
        }

        int32 realmID = -1;
        if (realmId)
            realmID = *realmId;

        uint32 playerSecurity;
        if (handler->IsConsole())
            playerSecurity = SEC_CONSOLE;
        else
            playerSecurity = AccountMgr::GetSecurity(handler->GetSession()->GetAccountId(), realmID);

        // can set security level only for target with less security and to less security that we have
        // This also restricts setting handler's own security.
        uint32 targetSecurity = AccountMgr::GetSecurity(accountId, realmID);
        if (targetSecurity >= playerSecurity || securityLevel >= playerSecurity)
        {
            handler->SendSysMessage(LANG_YOURS_SECURITY_IS_LOW);
            handler->SetSentErrorMessage(true);
            return false;
        }

        // Check and abort if the target gm has a higher rank on one of the realms and the new realm is -1
        if (realmID == -1 && !AccountMgr::IsConsoleAccount(playerSecurity))
        {
            LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_ACCOUNT_ACCESS_SECLEVEL_TEST);

            stmt->setUInt32(0, accountId);
            stmt->setUInt8(1, securityLevel);

            PreparedQueryResult result = LoginDatabase.Query(stmt);

            if (result)
            {
                handler->SendSysMessage(LANG_YOURS_SECURITY_IS_LOW);
                handler->SetSentErrorMessage(true);
                return false;
            }
        }

        // Check if provided realmID has a negative value other than -1
        if (realmID < -1)
        {
            handler->SendSysMessage(LANG_INVALID_REALMID);
            handler->SetSentErrorMessage(true);
            return false;
        }

        sAccountMgr->UpdateAccountAccess(nullptr, accountId, securityLevel, realmID);

        handler->PSendSysMessage(LANG_YOU_CHANGE_SECURITY, accountName->c_str(), securityLevel);
        return true;
    }

    /// Set password for account
    static bool HandleAccountSetPasswordCommand(ChatHandler *handler, std::string accountName, std::string const &password, std::string const &confirmPassword)
    {
        if (!Utf8ToUpperOnlyLatin(accountName))
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        uint32 targetAccountId = AccountMgr::GetId(accountName);
        if (!targetAccountId)
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        /// can set password only for target with less security
        /// This also restricts setting handler's own password
        if (handler->HasLowerSecurityAccount(nullptr, targetAccountId, true))
            return false;

        if (password != confirmPassword)
        {
            handler->SendSysMessage(LANG_NEW_PASSWORDS_NOT_MATCH);
            handler->SetSentErrorMessage(true);
            return false;
        }

        AccountOpResult result = AccountMgr::ChangePassword(targetAccountId, password);
        switch (result)
        {
        case AccountOpResult::AOR_OK:
            handler->SendSysMessage(LANG_COMMAND_PASSWORD);
            break;
        case AccountOpResult::AOR_NAME_NOT_EXIST:
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        case AccountOpResult::AOR_PASS_TOO_LONG:
            handler->SendSysMessage(LANG_PASSWORD_TOO_LONG);
            handler->SetSentErrorMessage(true);
            return false;
        default:
            handler->SendSysMessage(LANG_COMMAND_NOTCHANGEPASSWORD);
            handler->SetSentErrorMessage(true);
            return false;
        }
        return true;
    }

    static bool HandleAccountSet2FACommand(ChatHandler *handler, std::string accountName, std::string secret)
    {
        if (!Utf8ToUpperOnlyLatin(accountName))
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        uint32 targetAccountId = AccountMgr::GetId(accountName);
        if (!targetAccountId)
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        if (handler->HasLowerSecurityAccount(nullptr, targetAccountId, true))
            return false;

        if (secret == "off")
        {
            LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_ACCOUNT_TOTP_SECRET);
            stmt->setNull(0);
            stmt->setUInt32(1, targetAccountId);
            LoginDatabase.Execute(stmt);
            handler->PSendSysMessage(LANG_2FA_REMOVE_COMPLETE);
            return true;
        }

        auto const &masterKey = sSecretMgr->GetSecret(SECRET_TOTP_MASTER_KEY);
        if (!masterKey.IsAvailable())
        {
            handler->SendSysMessage(LANG_2FA_COMMANDS_NOT_SETUP);
            handler->SetSentErrorMessage(true);
            return false;
        }

        Optional<std::vector<uint8>> decoded = Trinity::Encoding::Base32::Decode(secret);
        if (!decoded)
        {
            handler->SendSysMessage(LANG_2FA_SECRET_INVALID);
            handler->SetSentErrorMessage(true);
            return false;
        }
        if (128 < (decoded->size() + Trinity::Crypto::AES::IV_SIZE_BYTES + Trinity::Crypto::AES::TAG_SIZE_BYTES))
        {
            handler->SendSysMessage(LANG_2FA_SECRET_TOO_LONG);
            handler->SetSentErrorMessage(true);
            return false;
        }

        if (masterKey)
            Trinity::Crypto::AEEncryptWithRandomIV<Trinity::Crypto::AES>(*decoded, *masterKey);

        LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_ACCOUNT_TOTP_SECRET);
        stmt->setBinary(0, *decoded);
        stmt->setUInt32(1, targetAccountId);
        LoginDatabase.Execute(stmt);
        handler->PSendSysMessage(LANG_2FA_SECRET_SET_COMPLETE, accountName.c_str());
        return true;
    }

    /// Set normal email for account
    static bool HandleAccountSetEmailCommand(ChatHandler *handler, std::string accountName, std::string const &email, std::string const &confirmEmail)
    {
        if (!Utf8ToUpperOnlyLatin(accountName))
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        uint32 targetAccountId = AccountMgr::GetId(accountName);
        if (!targetAccountId)
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        /// can set email only for target with less security
        /// This also restricts setting handler's own email.
        if (handler->HasLowerSecurityAccount(nullptr, targetAccountId, true))
            return false;

        if (email != confirmEmail)
        {
            handler->SendSysMessage(LANG_NEW_EMAILS_NOT_MATCH);
            handler->SetSentErrorMessage(true);
            return false;
        }

        AccountOpResult result = AccountMgr::ChangeEmail(targetAccountId, email);
        switch (result)
        {
        case AccountOpResult::AOR_OK:
            handler->SendSysMessage(LANG_COMMAND_EMAIL);
            TC_LOG_INFO("entities.player.character", "ChangeEmail: Account %s [Id: %u] had it's email changed to %s.",
                        accountName.c_str(), targetAccountId, email.c_str());
            break;
        case AccountOpResult::AOR_NAME_NOT_EXIST:
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        case AccountOpResult::AOR_EMAIL_TOO_LONG:
            handler->SendSysMessage(LANG_EMAIL_TOO_LONG);
            handler->SetSentErrorMessage(true);
            return false;
        default:
            handler->SendSysMessage(LANG_COMMAND_NOTCHANGEEMAIL);
            handler->SetSentErrorMessage(true);
            return false;
        }

        return true;
    }

    /// Change registration email for account
    static bool HandleAccountSetRegEmailCommand(ChatHandler *handler, std::string accountName, std::string const &email, std::string const &confirmEmail)
    {
        if (!Utf8ToUpperOnlyLatin(accountName))
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        uint32 targetAccountId = AccountMgr::GetId(accountName);
        if (!targetAccountId)
        {
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        /// can set email only for target with less security
        /// This also restricts setting handler's own email.
        if (handler->HasLowerSecurityAccount(nullptr, targetAccountId, true))
            return false;

        if (email != confirmEmail)
        {
            handler->SendSysMessage(LANG_NEW_EMAILS_NOT_MATCH);
            handler->SetSentErrorMessage(true);
            return false;
        }

        AccountOpResult result = AccountMgr::ChangeRegEmail(targetAccountId, email);
        switch (result)
        {
        case AccountOpResult::AOR_OK:
            handler->SendSysMessage(LANG_COMMAND_EMAIL);
            TC_LOG_INFO("entities.player.character", "ChangeRegEmail: Account %s [Id: %u] had it's Registration Email changed to %s.",
                        accountName.c_str(), targetAccountId, email.c_str());
            break;
        case AccountOpResult::AOR_NAME_NOT_EXIST:
            handler->PSendSysMessage(LANG_ACCOUNT_NOT_EXIST, accountName.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        case AccountOpResult::AOR_EMAIL_TOO_LONG:
            handler->SendSysMessage(LANG_EMAIL_TOO_LONG);
            handler->SetSentErrorMessage(true);
            return false;
        default:
            handler->SendSysMessage(LANG_COMMAND_NOTCHANGEEMAIL);
            handler->SetSentErrorMessage(true);
            return false;
        }

        return true;
    }
};

// #include <boost/beast/core.hpp>
// #include <boost/beast/http.hpp>
// #include <boost/beast/version.hpp>
// #include <boost/asio/coroutine.hpp>
// #include <boost/asio/dispatch.hpp>
// #include <boost/asio/strand.hpp>
// #include <boost/config.hpp>
// #include <algorithm>
// #include <cstdlib>
// #include <functional>
// #include <iostream>
// #include <memory>
// #include <string>
// #include <thread>
// #include <vector>
// #include <boost/json/src.hpp>
// namespace beast = boost::beast;   // from <boost/beast.hpp>
// namespace http = beast::http;     // from <boost/beast/http.hpp>
// namespace net = boost::asio;      // from <boost/asio.hpp>
// using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

// // Return a reasonable mime type based on the extension of a file.
// beast::string_view
// mime_type(beast::string_view path)
// {
//     using beast::iequals;
//     auto const ext = [&path]
//     {
//         auto const pos = path.rfind(".");
//         if (pos == beast::string_view::npos)
//             return beast::string_view{};
//         return path.substr(pos);
//     }();
//     if (iequals(ext, ".htm"))
//         return "text/html";
//     if (iequals(ext, ".html"))
//         return "text/html";
//     if (iequals(ext, ".php"))
//         return "text/html";
//     if (iequals(ext, ".css"))
//         return "text/css";
//     if (iequals(ext, ".txt"))
//         return "text/plain";
//     if (iequals(ext, ".js"))
//         return "application/javascript";
//     if (iequals(ext, ".json"))
//         return "application/json";
//     if (iequals(ext, ".xml"))
//         return "application/xml";
//     if (iequals(ext, ".swf"))
//         return "application/x-shockwave-flash";
//     if (iequals(ext, ".flv"))
//         return "video/x-flv";
//     if (iequals(ext, ".png"))
//         return "image/png";
//     if (iequals(ext, ".jpe"))
//         return "image/jpeg";
//     if (iequals(ext, ".jpeg"))
//         return "image/jpeg";
//     if (iequals(ext, ".jpg"))
//         return "image/jpeg";
//     if (iequals(ext, ".gif"))
//         return "image/gif";
//     if (iequals(ext, ".bmp"))
//         return "image/bmp";
//     if (iequals(ext, ".ico"))
//         return "image/vnd.microsoft.icon";
//     if (iequals(ext, ".tiff"))
//         return "image/tiff";
//     if (iequals(ext, ".tif"))
//         return "image/tiff";
//     if (iequals(ext, ".svg"))
//         return "image/svg+xml";
//     if (iequals(ext, ".svgz"))
//         return "image/svg+xml";
//     return "application/text";
// }


// // std::string
// // path_cat(
// //     beast::string_view path)
// // {
// // #ifdef BOOST_MSVC
// //     char constexpr path_separator = '\\';
// //     if (result.back() == path_separator)
// //         result.resize(result.size() - 1);
// //     result.append(path.data(), path.size());
// //     for (auto &c : result)
// //         if (c == '/')
// //             c = path_separator;
// // #else
// //     char constexpr path_separator = '/';
// //     if (result.back() == path_separator)
// //         result.resize(result.size() - 1);
// //     result.append(path.data(), path.size());
// // #endif
// //     return result;
// // }


// template <
//     class Body, class Allocator,
//     class Send>
// void handle_request(
//     beast::tcp_stream stream ,
//     http::request<Body, http::basic_fields<Allocator>> &&req,
//     Send &&send)
// {
//     // Returns a bad request response
//     auto const bad_request =
//         [&req](beast::string_view why)
//     {
//         http::response<http::string_body> res{http::status::bad_request, req.version()};
//         res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//         res.set(http::field::content_type, "text/html");
//         res.keep_alive(req.keep_alive());
//         res.body() = std::string(why);
//         res.prepare_payload();
//         return res;
//     };

//     // Returns a not found response
//     auto const not_found =
//         [&req](beast::string_view target)
//     {
//         http::response<http::string_body> res{http::status::not_found, req.version()};
//         res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//         res.set(http::field::content_type, "text/html");
//         res.keep_alive(req.keep_alive());
//         res.body() = "The resource '" + std::string(target) + "' was not found.";
//         res.prepare_payload();
//         return res;
//     };

//     // Returns a server error response
//     auto const server_error =
//         [&req](beast::string_view what)
//     {
//         http::response<http::string_body> res{http::status::internal_server_error, req.version()};
//         res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//         res.set(http::field::content_type, "text/html");
//         res.keep_alive(req.keep_alive());
//         res.body() = "An error occurred: '" + std::string(what) + "'";
//         res.prepare_payload();
//         return res;
//     };

//     // Make sure we can handle the method
//     if (req.method() != http::verb::get &&
//         req.method() != http::verb::head)
//         return send(bad_request("Unknown HTTP-method"));

//     // Request path must be absolute and not contain "..".
//     if (req.target().empty() ||
//         req.target()[0] != '/' ||
//         req.target().find("..") != beast::string_view::npos)
//         return send(bad_request("Illegal request-target"));

//     // Build the path to the requested file
//     std::string path = path_cat(req.target());
//     if (req.target() == "/registry")
//     {
//         boost::json::value decode;
//         std::cout << req.body() << std::endl;
//         decode = boost::json::parse(req.body());
//         WorldSession *session = new WorldSession(1, "", std::make_shared<WorldSocket>(std::move(stream.socket())), SEC_PLAYER, 0, 0, LOCALE_enUS, 0, false);
//         const std::string username = decode.at("account").as_string().data();
//         const std::string password = decode.at("password").as_string().data();
//         const std::string emailData = decode.at("email").as_string().data();
//         Optional<std::string> email = emailData;
//         ChatHandler *handler = new ChatHandler(session);
//         account_commandscript::HandleAccountCreateCommand(handler, username, password, email);

//         delete[] handler;
//         delete[] session;
//         http::response<http::string_body> res{http::status::ok, req.version()};
//         res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//         res.set(http::field::content_type, "text/plain");
//         res.keep_alive(req.keep_alive());
//         res.body() = "hello";
//         res.prepare_payload();
//         return send(std::move(res));
//     }

//     // Attempt to open the file
//     beast::error_code ec;
//     // http::file_body::value_type body;
//     // body.open(path.c_str(), beast::file_mode::scan, ec);

//     // Handle the case where the file doesn't exist
//     if (ec == beast::errc::no_such_file_or_directory)
//         return send(not_found(req.target()));

//     // Handle an unknown error
//     if (ec)
//         return send(server_error(ec.message()));

//     // Cache the size since we need it after the move
//     // auto const size = body.size();

//     // Respond to HEAD request
//     // if (req.method() == http::verb::head)
//     // {
//     //     http::response<http::empty_body> res{http::status::ok, req.version()};
//     //     res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//     //     res.set(http::field::content_type, mime_type(path));
//     //     res.content_length(size);
//     //     res.keep_alive(req.keep_alive());
//     //     return send(std::move(res));
//     // }

//     // Respond to GET request
//     // http::response<http::file_body> res{
//     //     std::piecewise_construct,
//     //     std::make_tuple(std::move(body)),
//     //     std::make_tuple(http::status::ok, req.version())};
//     // res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//     // res.set(http::field::content_type, mime_type(path));
//     // res.content_length(size);
//     // res.keep_alive(req.keep_alive());
//     // return send(std::move(res));
// }

// //------------------------------------------------------------------------------

// // Report a failure
// void fail(beast::error_code ec, char const *what)
// {
//     std::cerr << what << ": " << ec.message() << "\n";
// }

// // Handles an HTTP server connection
// class session
//     : public boost::asio::coroutine,
//       public std::enable_shared_from_this<session>
// {
//     // This is the C++11 equivalent of a generic lambda.
//     // The function object is used to send an HTTP message.
//     struct send_lambda
//     {
//         session &self_;
//         std::shared_ptr<void> res_;

//         explicit send_lambda(session &self)
//             : self_(self)
//         {
//         }

//         template <bool isRequest, class Body, class Fields>
//         void
//         operator()(http::message<isRequest, Body, Fields> &&msg) const
//         {
//             auto sp = std::make_shared<
//                 http::message<isRequest, Body, Fields>>(std::move(msg));

//             // Store a type-erased version of the shared
//             // pointer in the class to keep it alive.
//             self_.res_ = sp;

//             // Write the response
//             http::async_write(
//                 self_.stream_,
//                 *sp,
//                 beast::bind_front_handler(
//                     &session::loop,
//                     self_.shared_from_this(),
//                     sp->need_eof()));
//         }
//     };

//     beast::tcp_stream stream_;
//     beast::flat_buffer buffer_;
//     std::shared_ptr<std::string const> doc_root_;
//     http::request<http::string_body> req_;
//     std::shared_ptr<void> res_;
//     send_lambda lambda_;

// public:
//     // Take ownership of the socket
//     explicit session(
//         tcp::socket &&socket,
//         std::shared_ptr<std::string const> const &doc_root)
//         : stream_(std::move(socket)), doc_root_(doc_root), lambda_(*this)
//     {
//     }

//     // Start the asynchronous operation
//     void
//     run()
//     {
//         // We need to be executing within a strand to perform async operations
//         // on the I/O objects in this session. Although not strictly necessary
//         // for single-threaded contexts, this example code is written to be
//         // thread-safe by default.
//         net::dispatch(stream_.get_executor(),
//                       beast::bind_front_handler(&session::loop,
//                                                 shared_from_this(),
//                                                 false,
//                                                 beast::error_code{},
//                                                 0));
//     }

// #include <boost/asio/yield.hpp>

//     void
//     loop(
//         bool close,
//         beast::error_code ec,
//         std::size_t bytes_transferred)
//     {
//         boost::ignore_unused(bytes_transferred);
//         reenter(*this)
//         {
//             for (;;)
//             {
//                 // Make the request empty before reading,
//                 // otherwise the operation behavior is undefined.
//                 req_ = {};

//                 // Set the timeout.
//                 stream_.expires_after(std::chrono::seconds(30));

//                 // Read a request
//                 yield http::async_read(stream_, buffer_, req_,
//                                        beast::bind_front_handler(
//                                            &session::loop,
//                                            shared_from_this(),
//                                            false));
//                 if (ec == http::error::end_of_stream)
//                 {
//                     // The remote host closed the connection
//                     break;
//                 }
//                 if (ec)
//                     return fail(ec, "read");

//                 // Send the response
//                 yield handle_request(stream_, std::move(req_), lambda_);
//                 if (ec)
//                     return fail(ec, "write");
//                 if (close)
//                 {
//                     // This means we should close the connection, usually because
//                     // the response indicated the "Connection: close" semantic.
//                     break;
//                 }

//                 // We're done with the response so delete it
//                 res_ = nullptr;
//             }

//             // Send a TCP shutdown
//             stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

//             // At this point the connection is closed gracefully
//         }
//     }

// #include <boost/asio/unyield.hpp>
// };

// //------------------------------------------------------------------------------

// // Accepts incoming connections and launches the sessions
// class listener
//     : public boost::asio::coroutine,
//       public std::enable_shared_from_this<listener>
// {
//     net::io_context &ioc_;
//     tcp::acceptor acceptor_;
//     tcp::socket socket_;
//     std::shared_ptr<std::string const> doc_root_;

// public:
//     listener(
//         net::io_context &ioc,
//         tcp::endpoint endpoint,
//         std::shared_ptr<std::string const> const &doc_root)
//         : ioc_(ioc), acceptor_(net::make_strand(ioc)), socket_(net::make_strand(ioc)), doc_root_(doc_root)
//     {
//         beast::error_code ec;

//         // Open the acceptor
//         acceptor_.open(endpoint.protocol(), ec);
//         if (ec)
//         {
//             fail(ec, "open");
//             return;
//         }

//         // Allow address reuse
//         acceptor_.set_option(net::socket_base::reuse_address(true), ec);
//         if (ec)
//         {
//             fail(ec, "set_option");
//             return;
//         }

//         // Bind to the server address
//         acceptor_.bind(endpoint, ec);
//         if (ec)
//         {
//             fail(ec, "bind");
//             return;
//         }

//         // Start listening for connections
//         acceptor_.listen(net::socket_base::max_listen_connections, ec);
//         if (ec)
//         {
//             fail(ec, "listen");
//             return;
//         }
//     }

//     // Start accepting incoming connections
//     void
//     run()
//     {
//         loop();
//     }

// private:
// #include <boost/asio/yield.hpp>

//     void
//     loop(beast::error_code ec = {})
//     {
//         reenter(*this)
//         {
//             for (;;)
//             {
//                 yield acceptor_.async_accept(
//                     socket_,
//                     beast::bind_front_handler(
//                         &listener::loop,
//                         shared_from_this()));
//                 if (ec)
//                 {
//                     fail(ec, "accept");
//                 }
//                 else
//                 {
//                     // Create the session and run it
//                     std::make_shared<session>(
//                         std::move(socket_),
//                         doc_root_)
//                         ->run();
//                 }

//                 // Make sure each session gets its own strand
//                 socket_ = tcp::socket(net::make_strand(ioc_));
//             }
//         }
//     }

// #include <boost/asio/unyield.hpp>
// };

// //------------------------------------------------------------------------------

// int main()
// {

//     auto const address = net::ip::make_address("0.0.0.0");
//     auto const port = static_cast<unsigned short>(std::atoi("8080"));
//     auto const doc_root = std::make_shared<std::string>("");
//     auto const threads = std::max<int>(1, std::atoi("1"));

//     net::io_context ioc{threads};

//     std::make_shared<listener>(
//         ioc,
//         tcp::endpoint{address, port},
//         doc_root)
//         ->run();

//     std::vector<std::thread> v;
//     v.reserve(threads - 1);
//     for (auto i = threads - 1; i > 0; --i)
//         v.emplace_back(
//             [&ioc]
//             {
//                 ioc.run();
//             });
//     ioc.run();

//     return EXIT_SUCCESS;
// }
// std::thread t1(&main);

void AddSC_account_commandscript()
{
    new account_commandscript();
}
