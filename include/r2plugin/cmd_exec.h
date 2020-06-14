/**
 * @file include/r2plugin/cmd_exec.h
 * @brief Implements command execution logic for supported OSs.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#ifndef R2PLUGIN_CMD_RUNNER_H
#define R2PLUGIN_CMD_RUNNER_H

#include <vector>
#include <string>

namespace retdec {
namespace r2plugin {

/**
 * Provides interface for command running.
 */
class CmdExec {
private:
	/// Private destructor -> instantiation is not wanted.
	~CmdExec();

public:
	static void execute(
		const std::string &interpret,
		const std::string &cmd,
		const std::vector<std::string> &args,
		const std::string &outRedir = "",
		const std::string &errRedir = "");


	static std::string sanitizePath(const std::string &path);

public:
	static std::string NUL;

protected:
	static std::string prepareCommandParams(const std::vector<std::string> &args);
	static std::string prepareCommand(const std::string &cmd);

	static std::string doSanitizePath(
		const std::string &path,
		char quoteType,
		const std::string &sanitized);
};

/**
 * Represents execution exception -> any execution complications resulting
 * in error are represented by instances of this class.
 */
class ExecutionError: public std::exception {
public:
	ExecutionError(const std::string &msg) : _message(msg) {}
	~ExecutionError() throw() {}
	const char* what() const throw() { return _message.c_str(); }

private:
	std::string _message;
};

}
}

#endif /*R2PLUGIN_CMD_RUNNER_H*/
