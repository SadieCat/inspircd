/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2018 Peter Powell <petpow@saberuk.com>
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

struct Attribute
{
	virtual ~Attribute()
	{
	}

	/** Change the value of this attribute.
	 * @param target The user to change the attribute of.
	 * @param value The new value for the attribute.
	 */
	virtual void ChangeValue(User* target, const std::string& value) const = 0;

	/** Check the syntax of a potential value.
	 * @param value The potential value to check.
	 * @return True if the length of the potential attribute is acceptable; otherwise, false.
	 */
	virtual bool SyntaxCheck(const std::string& value) const = 0;
};

static std::bitset<UCHAR_MAX> validhostchars;

struct HostAttribute
	: public Attribute
{
	void ChangeValue(User* target, const std::string& value) const CXX11_OVERRIDE
	{
		target->ChangeDisplayedHost(value);
	}

	bool SyntaxCheck(const std::string& value) const CXX11_OVERRIDE
	{
		if (value.length() > ServerInstance->Config->Limits.MaxHost)
			return false;

		for (std::string::const_iterator iter = value.begin(); iter != value.end(); ++iter)
		{
			if (!validhostchars.test(static_cast<unsigned char>(*iter)))
				return false;
		}
		return true;
	}
};

struct NickAttribute
	: public Attribute
{
	void ChangeValue(User* target, const std::string& value) const CXX11_OVERRIDE
	{
		target->ChangeNick(value);
	}

	bool SyntaxCheck(const std::string& value) const CXX11_OVERRIDE
	{
		return ServerInstance->IsNick(value);
	}
};

struct RealAttribute
	: public Attribute
{
	void ChangeValue(User* target, const std::string& value) const CXX11_OVERRIDE
	{
		target->ChangeRealName(value);
	}

	bool SyntaxCheck(const std::string& value) const CXX11_OVERRIDE
	{
		return value.length() <= ServerInstance->Config->Limits.MaxReal;
	}
};

struct UserAttribute
	: public Attribute
{
	void ChangeValue(User* target, const std::string& value) const CXX11_OVERRIDE
	{
		target->ChangeIdent(value);
	}

	bool SyntaxCheck(const std::string& value) const CXX11_OVERRIDE
	{
		if (value.length() > ServerInstance->Config->Limits.IdentMax)
			return false;

		return ServerInstance->IsIdent(value);
	}
};

class CommandUserMod : public Command
{
 private:
	typedef insp::flat_map<std::string, Attribute*, irc::insensitive_swo> AttributeMap;
	AttributeMap attributes;

	CmdResult ModifyUser(User* source, User* target, const std::string& attribute, const std::string& value)
	{
		// Check the source wants to change a valid attribute.
		AttributeMap::const_iterator iter = attributes.find(attribute);
		if (iter == attributes.end())
		{
			source->WriteNotice("*** USERMOD: " + attribute + " is not a valid user attribute!");
			return CMD_FAILURE;
		}

		// Check the source has the right privs.
		const std::string priv = InspIRCd::Format("usermod/%s-%s", attribute.c_str(), source == target ? "self" : "others");
		if (!source->HasPrivPermission(priv))
		{
			source->WriteNotice(InspIRCd::Format("*** USERMOD: The %s oper privilege is required to change %s's %s!",
					priv.c_str(), target->nick.c_str(), attribute.c_str()));
			return CMD_FAILURE;
		}

		// Check the attribute 
		const Attribute* attrib = iter->second;
		if (attrib->SyntaxCheck(value))
		{
			source->WriteNotice("*** USERMOD: The " + attribute + " you specified is not valid!");
			return CMD_FAILURE;
		}

		if (IS_LOCAL(target))
			attrib->ChangeValue(target, value);

		return CMD_SUCCESS;
	}

 public:
	CommandUserMod(Module* Creator)
		: Command(Creator, "USERMOD", 2, 3)
	{
		allow_empty_last_param = false;
		flags_needed = 'o';
		syntax = "<attribute> [nick] <new value>";
		TRANSLATE3(TR_TEXT, TR_NICK, TR_TEXT);

		attributes["host"] = new HostAttribute();
		attributes["nick"] = new NickAttribute();
		attributes["real"] = new RealAttribute();
		attributes["user"] = new UserAttribute();
	}

	~CommandUserMod()
	{
		for (AttributeMap::const_iterator iter = attributes.begin(); iter != attributes.end(); ++iter)
			delete iter->second;
	}

	CmdResult Handle(User* user, const Params& parameters) CXX11_OVERRIDE
	{
		// Two parameters means the user is changing their own attributes.
		if (parameters.size() == 2)
			return ModifyUser(user, user, parameters[0], parameters[1]);

		// Check that the target exists and is registered.
		User* target = ServerInstance->FindNick(parameters[1]);
		if (!target || target->registered != REG_ALL)
		{
			user->WriteNumeric(Numerics::NoSuchNick(parameters[1]));
			return CMD_FAILURE;
		}

		return ModifyUser(user, target, parameters[0], parameters[1]);
	}

	RouteDescriptor GetRouting(User* user, const Params& parameters) CXX11_OVERRIDE
	{
		return ROUTE_UNICAST(parameters.size() == 3 ? parameters[1] : user->nick);
	}
};

class ModuleUserMod : public Module
{
 private:
	CommandUserMod cmd;

 public:
	ModuleUserMod()
		: cmd(this)
	{
	}

	void ReadConfig(ConfigStatus& status) CXX11_OVERRIDE
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("hostname");
		const std::string hostchars = tag->getString("charmap", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-_/0123456789");

		validhostchars.reset();
		for (std::string::const_iterator iter = hostchars.begin(); iter != hostchars.end(); ++iter)
			validhostchars.set(static_cast<unsigned char>(*iter));
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Provides support for the USERMOD command", VF_COMMON|VF_VENDOR);
	}
};

MODULE_INIT(ModuleUserMod)
