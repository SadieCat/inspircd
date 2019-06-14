/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2016 Attila Molnar <attilamolnar@hush.com>
 *   Copyright (C) 2018-2019 Peter Powell <petpow@saberuk.com>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "modules/cap.h"
#include "modules/ircv3_batch.h"

class LabeledResponseTag : public ClientProtocol::MessageTagProvider
{
 private:
	const Cap::Capability& cap;

 public:
	LabeledResponseTag(Module* mod, const Cap::Capability& capref)
		: ClientProtocol::MessageTagProvider(mod)
		, cap(capref)
	{
	}

	ModResult OnProcessTag(User* user, const std::string& tagname, std::string& tagvalue) CXX11_OVERRIDE
	{
		if (!irc::equals(tagname, "draft/label"))
			return MOD_RES_PASSTHRU;

		// If the tag is empty or too long then we can't accept it.
		if (tagvalue.empty() || tagvalue.size() > 64)
			return MOD_RES_DENY;

		// If the user is local then we check whether they have the labeled-response
		// cap enabled. If not then we reject the label tag originating from them.
		LocalUser* lu = IS_LOCAL(user);
		if (lu && !cap.get(lu))
			return MOD_RES_DENY;

		// Remote users have their label tag checked by their local server.
		return MOD_RES_ALLOW;
	}

	bool ShouldSendTag(LocalUser* user, const ClientProtocol::MessageTagData& tagdata) CXX11_OVERRIDE
	{
		// Messages only have a label when being sent to a user that sent one.
		return true;
	}
};

class ModuleIRCv3LabeledResponse : public Module
{
 private:
	Cap::Capability cap;
	LabeledResponseTag tag;
	IRCv3::Batch::API batchmanager;
	IRCv3::Batch::Batch batch;
	ClientProtocol::EventProvider ackmsgprov;
	ClientProtocol::EventProvider labelmsgprov;
	insp::aligned_storage<ClientProtocol::Message> firstmsg;
	size_t msgcount;
	LocalUser* labeluser;
	std::string label;

	void FlushFirstMsg(LocalUser* user)
	{
		// This isn't a side effect but we treat it like one to avoid the logic in OnUserWrite.
		firstmsg->SetSideEffect(true);
		user->Send(labelmsgprov, *firstmsg);
		firstmsg->~Message();
	}

 public:
	ModuleIRCv3LabeledResponse()
		: cap(this, "draft/labeled-response-0.2")
		, tag(this, cap)
		, batchmanager(this)
		, batch("draft/labeled-response")
		, ackmsgprov(this, "ACK")
		, labelmsgprov(this, "labeled")
		, msgcount(0)
		, labeluser(NULL)

	{
	}

	ModResult OnPreCommand(std::string& command, CommandBase::Params& parameters, LocalUser* user, bool validated) CXX11_OVERRIDE
	{
		// If a command has not been fully validated it may be changed.i
		if (!validated)
			return MOD_RES_PASSTHRU;

		// We only care about registered users with the labeled-response cap.
		if (user->registered != REG_ALL || !cap.get(user))
			return MOD_RES_PASSTHRU;

		// If the server has executed commands for the user ignore them.
		if (labeluser)
			return MOD_RES_PASSTHRU;

		const ClientProtocol::TagMap& tagmap = parameters.GetTags();
		const ClientProtocol::TagMap::const_iterator labeltag = tagmap.find("draft/label");
		if (labeltag == tagmap.end())
			return MOD_RES_PASSTHRU;

		label = labeltag->second.value;
		labeluser = user;
		return MOD_RES_PASSTHRU;
	}

	void OnPostCommand(Command* command, const CommandBase::Params& parameters, LocalUser* user, CmdResult result, bool loop) CXX11_OVERRIDE
	{
		// Do nothing if this isn't the last OnPostCommand() run for the command.
		//
		// If a parameter for the command was originally a list and the command handler chose to be executed
		// for each element on the list with synthesized parameters (CommandHandler::LoopCall) then this hook
		// too will run for each element on the list plus once after the whole list has been processed.
		// loop will only be false for the last run.
		if (loop)
			return;

		// If no label was sent we don't have to do anything.
		if (!labeluser)
			return;

		switch (msgcount)
		{
			case 0:
			{
				// There was no response so we send an ACK instead.
				ClientProtocol::Message ackmsg("ACK", ServerInstance->FakeClient);
				ackmsg.AddTag("draft/label", &tag, label);
				ackmsg.SetSideEffect(true);
				labeluser->Send(ackmsgprov, ackmsg);
				break;
			}

			case 1:
			{
				// There was one response which was cached; send it now.
				firstmsg->AddTag("draft/label", &tag, label);
				FlushFirstMsg(user);
				break;
			}

			default:
			{
				// There was two or more responses; send an end-of-batch.
				if (batchmanager)
				{
					// Set end start as side effect so we'll ignore it otherwise it'd end up added into the batch.
					ClientProtocol::Message& batchendmsg = batch.GetBatchEndMessage();
					batchendmsg.SetSideEffect(true);

					batchmanager->End(batch);
				}
				break;
			}
		}

		labeluser = NULL;
		msgcount = 0;
	}

	ModResult OnUserWrite(LocalUser* user, ClientProtocol::Message& msg) CXX11_OVERRIDE
	{
		// The label user is writing a message to another user.
		if (user != labeluser)
			return MOD_RES_PASSTHRU;

		// The message is a side effect (e.g. a self-PRIVMSG).
		if (msg.IsSideEffect())
			return MOD_RES_PASSTHRU;

		switch (++msgcount)
		{
			case 1:
			{
				// First reply message. We can' send it yet because we don't know if there will be more.
				new(firstmsg) ClientProtocol::Message(msg);
				firstmsg->CopyAll();
				return MOD_RES_DENY;
			}

			case 2:
			{
				// Second reply message. This and all subsequent messages need to go into a batch.
				if (batchmanager)
				{
					batchmanager->Start(batch);

					// Set batch start as side effect so we'll ignore it otherwise it'd end up added into the batch.
					ClientProtocol::Message& batchstartmsg = batch.GetBatchStartMessage();
					batchstartmsg.SetSideEffect(true);
					batchstartmsg.AddTag("draft/label", &tag, label);

					batch.AddToBatch(*firstmsg);
					batch.AddToBatch(msg);
				}

				// Flush first message which triggers the batch start message
				FlushFirstMsg(user);
				return MOD_RES_PASSTHRU;
			}

			default:
			{
				// Third or later message. Put it in the batch and send directly.
				if (batchmanager)
					batch.AddToBatch(msg);
				return MOD_RES_PASSTHRU;
			}
		}
	}

	void Prioritize() CXX11_OVERRIDE
	{
		ServerInstance->Modules.SetPriority(this, I_OnPreCommand, PRIORITY_LAST);
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Provides the DRAFT labeled-response IRCv3 extension", VF_VENDOR);
	}
};

MODULE_INIT(ModuleIRCv3LabeledResponse)
