/*



*/


#ifndef __PLUGIN_H
#define __PLUGIN_H

#define DEBUG 10
#define VERBOSE 20
#define DEFAULT 30
#define SPARSE 40
#define NONE 50

#define MT_CHANNEL 1
#define MT_CLIENT 2
#define MT_SERVER 3

#include "dynamic.h"
#include "base.h"
#include <string>
#include <deque>

/** Low level definition of a FileReader classes file cache area
 */
typedef deque<string> file_cache;
typedef file_cache string_list;

// This #define allows us to call a method in all
// loaded modules in a readable simple way, e.g.:
// 'FOREACH_MOD OnConnect(user);'

#define FOREACH_MOD for (int i = 0; i <= MODCOUNT; i++) modules[i]->

// class Version holds the version information of a Module, returned
// by Module::GetVersion (thanks RD)

/** Holds a module's Version information
 *  The four members (set by the constructor only) indicate details as to the version number
 *  of a module. A class of type Version is returned by the GetVersion method of the Module class.
 */
class Version : public classbase
{
 public:
	 const int Major, Minor, Revision, Build;
	 Version(int major, int minor, int revision, int build);
};

/** Holds /ADMIN data
 *  This class contains the admin details of the local server. It is constructed by class Server,
 *  and has three read-only values, Name, Email and Nick that contain the specified values for the
 *  server where the module is running.
 */
class Admin : public classbase
{
 public:
	 const string Name, Email, Nick;
	 Admin(string name,string email,string nick);
};

/** Base class for all InspIRCd modules
 *  This class is the base class for InspIRCd modules. All modules must inherit from this class,
 *  its methods will be called when irc server events occur. class inherited from module must be
 *  instantiated by the ModuleFactory class (see relevent section) for the plugin to be initialised.
 */
class Module : public classbase
{
 public:

	/** Default constructor
	 * creates a module class
	 */
	Module();

	/** Default destructor
	 * destroys a module class
	 */
	virtual ~Module();

	/** Returns the version number of a Module.
	 * The method should return a Version object with its version information assigned via
	 * Version::Version
	 */
	virtual Version GetVersion();

	/** Called when a user connects.
	 * The details of the connecting user are available to you in the parameter userrec *user
	 */
	virtual void OnUserConnect(userrec* user);

	/** Called when a user quits.
	 * The details of the exiting user are available to you in the parameter userrec *user
	 */
	virtual void OnUserQuit(userrec* user);

	/** Called when a user joins a channel.
	 * The details of the joining user are available to you in the parameter userrec *user,
	 * and the details of the channel they have joined is available in the variable chanrec *channel
	 */
	virtual void OnUserJoin(userrec* user, chanrec* channel);

	/** Called when a user parts a channel.
	 * The details of the leaving user are available to you in the parameter userrec *user,
	 * and the details of the channel they have left is available in the variable chanrec *channel
	 */
	virtual void OnUserPart(userrec* user, chanrec* channel);

	/** Called before a packet is transmitted across the irc network between two irc servers.
	 * The packet is represented as a char*, as it should be regarded as a buffer, and not a string.
	 * This allows you to easily represent it in the correct ways to implement encryption, compression,
	 * digital signatures and anything else you may want to add. This should be regarded as a pre-processor
	 * and will be called before ANY other operations within the ircd core program.
	 */
	virtual void Module::OnPacketTransmit(char *p);

	/** Called after a packet is received from another irc server.
	 * The packet is represented as a char*, as it should be regarded as a buffer, and not a string.
	 * This allows you to easily represent it in the correct ways to implement encryption, compression,
	 * digital signatures and anything else you may want to add. This should be regarded as a pre-processor
	 * and will be called immediately after the packet is received but before any other operations with the
	 * core of the ircd.
	 */
 	virtual void Module::OnPacketReceive(char *p);

	/** Called on rehash.
	 * This method is called prior to a /REHASH or when a SIGHUP is received from the operating
	 * system. You should use it to reload any files so that your module keeps in step with the
	 * rest of the application.
	 */
 	virtual void OnRehash();

	/** Called when a raw command is transmitted or received.
	 * This method is the lowest level of handler available to a module. It will be called with raw
	 * data which is passing through a connected socket. If you wish, you may munge this data by changing
	 * the string parameter "raw". If you do this, after your function exits it will immediately be
	 * cut down to 510 characters plus a carriage return and linefeed.
	 */
 	virtual void OnServerRaw(string &raw, bool inbound);

	/** Called whenever an extended mode is to be processed.
	 * The type parameter is MT_SERVER, MT_CLIENT or MT_CHANNEL, dependent on where the mode is being
	 * changed. mode_on is set when the mode is being set, in which case params contains a list of
	 * parameters for the mode as strings. If mode_on is false, the mode is being removed, and parameters
	 * may contain the parameters for the mode, dependent on wether they were defined when a mode handler
 	 * was set up with Server::AddExtendedMode
 	 * If the mode is not a channel mode, chanrec* chan is null, and should not be read from or written to.
	 */
 	virtual bool OnExtendedMode(userrec* user, chanrec* chan, char modechar, int type, bool mode_on, string_list &params);
	 
};


/** Allows server output and query functions
 * This class contains methods which allow a module to query the state of the irc server, and produce
 * output to users and other servers. All modules should instantiate at least one copy of this class,
 * and use its member functions to perform their tasks.
 */
class Server : public classbase
{
 public:
	/** Default constructor.
	 * Creates a Server object.
	 */
	Server();
	/** Default destructor.
	 * Destroys a Server object.
	 */
	virtual ~Server();

	/** Sends text to all opers.
	 * This method sends a server notice to all opers with the usermode +s.
	 */
	virtual void SendOpers(string s);
	/** Writes a log string.
	 * This method writes a line of text to the log. If the level given is lower than the
	 * level given in the configuration, this command has no effect.
	 */
	virtual void Log(int level, string s);
	/** Sends a line of text down a TCP/IP socket.
	 * This method writes a line of text to an established socket, cutting it to 510 characters
	 * plus a carriage return and linefeed if required.
	 */
	virtual void Send(int Socket, string s);
	/** Sends text from the server to a socket.
	 * This method writes a line of text to an established socket, with the servername prepended
	 * as used by numerics (see RFC 1459)
	 */
	virtual void SendServ(int Socket, string s);
	/** Sends text from a user to a socket.
	 * This method writes a line of text to an established socket, with the given user's nick/ident
	 * /host combination prepended, as used in PRIVSG etc commands (see RFC 1459)
	 */
	virtual void SendFrom(int Socket, userrec* User, string s);
	/** Sends text from a user to another user.
	 * This method writes a line of text to a user, with a user's nick/ident
	 * /host combination prepended, as used in PRIVMSG etc commands (see RFC 1459)
	 */
	virtual void SendTo(userrec* Source, userrec* Dest, string s);
	/** Sends text from a user to a channel (mulicast).
	 * This method writes a line of text to a channel, with the given user's nick/ident
	 * /host combination prepended, as used in PRIVMSG etc commands (see RFC 1459). If the
	 * IncludeSender flag is set, then the text is also sent back to the user from which
	 * it originated, as seen in MODE (see RFC 1459).
	 */
	virtual void SendChannel(userrec* User, chanrec* Channel, string s,bool IncludeSender);
	/** Returns true if two users share a common channel.
	 * This method is used internally by the NICK and QUIT commands, and the Server::SendCommon
	 * method.
	 */
	virtual bool CommonChannels(userrec* u1, userrec* u2);
	/** Sends text from a user to one or more channels (mulicast).
	 * This method writes a line of text to all users which share a common channel with a given	
	 * user, with the user's nick/ident/host combination prepended, as used in PRIVMSG etc
	 * commands (see RFC 1459). If the IncludeSender flag is set, then the text is also sent
	 * back to the user from which it originated, as seen in NICK (see RFC 1459). Otherwise, it
	 * is only sent to the other recipients, as seen in QUIT.
	 */
	virtual void SendCommon(userrec* User, string text,bool IncludeSender);
	/** Sends a WALLOPS message.
	 * This method writes a WALLOPS message to all users with the +w flag, originating from the
	 * specified user.
	 */
	virtual void SendWallops(userrec* User, string text);

	/** Returns true if a nick is valid.
	 * Nicks for unregistered connections will return false.
	 */
	virtual bool IsNick(string nick);
	/** Attempts to look up a nick and return a pointer to it.
	 * This function will return NULL if the nick does not exist.
	 */
	virtual userrec* FindNick(string nick);
	/** Attempts to look up a channel and return a pointer to it.
	 * This function will return NULL if the channel does not exist.
	 */
	virtual chanrec* FindChannel(string channel);
	/** Attempts to look up a user's privilages on a channel.
	 * This function will return a string containing either @, %, +, or an empty string,
	 * representing the user's privilages upon the channel you specify.
	 */
	virtual string ChanMode(userrec* User, chanrec* Chan);
	/** Returns the server name of the server where the module is loaded.
	 */
	virtual string GetServerName();
	/** Returns the network name, global to all linked servers.
	 */
	virtual string GetNetworkName();
	/** Returns the information of the server as returned by the /ADMIN command.
	 * See the Admin class for further information of the return value. The members
	 * Admin::Nick, Admin::Email and Admin::Name contain the information for the
	 * server where the module is loaded.
	 */
	virtual Admin GetAdmin();
	/** Adds an extended mode letter which is parsed by a module
	 * This allows modules to add extra mode letters, e.g. +x for hostcloak.
	 * the "type" parameter is either MT_CHANNEL, MT_CLIENT, or MT_SERVER, to
	 * indicate wether the mode is a channel mode, a client mode, or a server mode.
	 * default_on is true if the mode is to be applied to default connections.
	 * params_when_on is the number of modes to expect when the mode is turned on
	 * (for type MT_CHANNEL only), e.g. with mode +b, this would have a value of 1.
	 * the params_when_off value has a similar value to params_when_on, except it indicates
	 * the number of parameters to expect when the mode is disabled. Modes which act in a similar
	 * way to channel mode +l (e.g. require a parameter to enable, but not to disable) should
	 * use this parameter. The function returns false if the mode is unavailable, and will not
	 * attempt to allocate another character, as this will confuse users. This also means that
	 * as only one module can claim a specific mode character, the core does not need to keep track
	 * of which modules own which modes, which speeds up operation of the server. In this version,
	 * a mode can have at most one parameter, attempting to use more parameters will have undefined
	 * effects.
	 */
	virtual bool AddExtendedMode(char modechar, int type, bool default_on, int params_when_on, int params_when_off);
	 
};

/** Allows reading of values from configuration files
 * This class allows a module to read from either the main configuration file (inspircd.conf) or from
 * a module-specified configuration file. It may either be instantiated with one parameter or none.
 * Constructing the class using one parameter allows you to specify a path to your own configuration
 * file, otherwise, inspircd.conf is read.
 */
class ConfigReader : public classbase
{
  protected:
	/** The filename of the configuration file, as set by the constructor.
	 */
	string fname;
  public:
	/** Default constructor.
	 * This constructor initialises the ConfigReader class to read the inspircd.conf file
	 * as specified when running ./configure.
	 */
	ConfigReader(); 		// default constructor reads ircd.conf
	/** Overloaded constructor.
	 * This constructor initialises the ConfigReader class to read a user-specified config file
	 */
	ConfigReader(string filename);	// read a module-specific config
	/** Default destructor.
	 * This method destroys the ConfigReader class.
	 */
	~ConfigReader();
	/** Retrieves a value from the config file.
	 * This method retrieves a value from the config file. Where multiple copies of the tag
	 * exist in the config file, index indicates which of the values to retrieve.
	 */
	string ReadValue(string tag, string name, int index);
	/** Counts the number of times a given tag appears in the config file.
	 * This method counts the number of times a tag appears in a config file, for use where
	 * there are several tags of the same kind, e.g. with opers and connect types. It can be
	 * used with the index value of ConfigReader::ReadValue to loop through all copies of a
	 * multiple instance tag.
	 */
	int Enumerate(string tag);
	/** Returns true if a config file is valid.
	 * This method is unimplemented and will always return true.
	 */
	bool Verify();
};



/** Caches a text file into memory and can be used to retrieve lines from it.
 * This class contains methods for read-only manipulation of a text file in memory.
 * Either use the constructor type with one parameter to load a file into memory
 * at construction, or use the LoadFile method to load a file.
 */
class FileReader : public classbase
{
 file_cache fc;
 public:
	 /** Default constructor.
	  * This method does not load any file into memory, you must use the LoadFile method
	  * after constructing the class this way.
	  */
	 FileReader();
	 /** Secondary constructor.
	  * This method initialises the class with a file loaded into it ready for GetLine and
	  * and other methods to be called. If the file could not be loaded, FileReader::FileSize
	  * returns 0.
	  */
	 FileReader(string filename);
	 /** Default destructor.
	  * This deletes the memory allocated to the file.
	  */
	 ~FileReader();
	 /** Used to load a file.
	  * This method loads a file into the class ready for GetLine and
	  * and other methods to be called. If the file could not be loaded, FileReader::FileSize
	  * returns 0.
	  */
	 void LoadFile(string filename);
	 /** Retrieve one line from the file.
	  * This method retrieves one line from the text file. If an empty non-NULL string is returned,
	  * the index was out of bounds, or the line had no data on it.
	  */
	 string GetLine(int x);
	 /** Returns the size of the file in lines.
	  * This method returns the number of lines in the read file. If it is 0, no lines have been
	  * read into memory, either because the file is empty or it does not exist, or cannot be
	  * opened due to permission problems.
	  */
	 int FileSize();
};


/** Instantiates classes inherited from Module
 * This class creates a class inherited from type Module, using new. This is to allow for modules
 * to create many different variants of Module, dependent on architecture, configuration, etc.
 * In most cases, the simple class shown in the example module m_foobar.so will suffice for most
 * modules.
 */
class ModuleFactory : public classbase
{
 public:
	ModuleFactory() { }
	virtual ~ModuleFactory() { }
	/** Creates a new module.
	 * Your inherited class of ModuleFactory must return a pointer to your Module class
	 * using this method.
	 */
	virtual Module * CreateModule() = 0;
};


typedef DLLFactory<ModuleFactory> ircd_module;

#endif
