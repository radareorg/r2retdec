/**
 * @file src/cmd_exec.cpp
 * @brief Implements command execution logic for supported OSs.
 * @copyright (c) 2020 Avast Software, licensed under the LGPLv3 license.
 */

#include <cassert>
#include <sstream>

#include "r2plugin/cmd_exec.h"
#include "r2plugin/r2utils.h"

#include "filesystem_wrapper.h"

using namespace retdec::r2plugin;
using fu = retdec::r2plugin::FormatUtils;

CmdExec::~CmdExec()
{
}

/**
 * @brief Run specified command, with specified parameters and output redirection.
 *
 * @param interpret Provides program that will interpet the cmd. In case of executable empty string should be provided.
 * @param cmd      Command to be runned. In case of full path of the executable the path must be sanitized
 *                 and existence of the executable should be verified before calling this function.
 * @param args     Parameters of the command. No sanitization is provided. If a parameter contains spaces
 *                 it will probably be interprated as two parameters.
 * @param outRedir File where output will be redirected. No sanitization is provided and existence of file
 *                 is not verified.
 * @param errRedir File where stderr will be redirected. No sanitization iw provided and existence of file
 * 		   is not verified.
 */
void CmdExec::execute(
		const std::string &interpret,
		const std::string &cmd,
		const std::vector<std::string> &args,
		const std::string &outRedir,
		const std::string &errRedir)
{
	// Make sure at least one is assigned.
	assert(
		!(interpret.empty() && cmd.empty())
		&& "Neither interpet nor cmd were provided."
	);

	std::string systemCMD = "";
	if (!interpret.empty())
		systemCMD += interpret + " ";

	if (!cmd.empty())
		systemCMD += prepareCommand(cmd) + " ";

	systemCMD += prepareCommandParams(args);

	if (outRedir != "")
		systemCMD += " > " + outRedir;

	if (errRedir != "")
		systemCMD += " 2> " + errRedir;

	if (int exitCode = system(systemCMD.c_str()))
		throw ExecutionError("exit code: "+std::to_string(exitCode));
}

/**
 * @brief Prepares parameters of a runnable command.
 *
 * Joins parameters as tokens separated with spaces. Each parameter
 * must be properly sanitized before calling this function.
 */
std::string CmdExec::prepareCommandParams(const std::vector<std::string> &args)
{
	return fu::joinTokens(args, " ");
}

/**
 * @brief Preapre command for running.
 *
 * This function is dedicated for preparation of command for running.
 * Right now this function only returns its input on output.
 */
std::string CmdExec::prepareCommand(const std::string &cmd)
{
	return cmd;
}

/**
 * @brief Provides sanitization of a command path.
 *
 * Purpose of this function is to solve problem when an user
 * specified paths contain spaces. This would result for example in
 * misinterpratation of the program and its args.
 * Sanitization is provided by wrapping the command in double
 * qoutes -> existing double qoutes must be escaped.
 *
 * Example unix:
 *  User input: /home/user/'my' dir/retdec-decompiler.py
 *  Fnc output: '/home/user/my'\'' dir/retdec-decompiler.py'
 *
 * Example windows:
 *  User input: /home/user/"my" dir/retdec-decompiler.py
 *  Fnc output: "/home/user/my'\'' dir/retdec-decompiler.py"
 *
 *  On windows quotes (") are not allowed as file names
 *  and migh help in command injection. This is why (")
 *  are deleted.
 *
 * @param path Full path of the command.
 */
std::string CmdExec::sanitizePath(const std::string &path)
{
#if defined(unix) || defined(__unix__) || defined(__unix) || defined(__APPLE__)
	return doSanitizePath(path, '\'', "'\\''");

#elif defined(_WIN32)
	return doSanitizePath(path, '\"', "");

#else
	return path;

#endif
}

/**
 * @brief Provides sanitization logic.
 */
std::string CmdExec::doSanitizePath(
		const std::string &path,
		char quoteType,
		const std::string &sanitized)
{
	if (path.empty())
		return path;

	std::ostringstream str;
	str << quoteType;
	for (char c: path) {
		if (c == quoteType)
			str << sanitized;
		else
			str << c;
	}
	str << quoteType;

	return str.str();
}

#if defined(unix) || defined(__unix__) || defined(__unix) || defined(__APPLE__)
	std::string CmdExec::NUL = "/dev/null";
#else
	std::string CmdExec::NUL = "nul";
#endif
