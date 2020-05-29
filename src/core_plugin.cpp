/**
 * @file src/core_plugin.cpp
 * @brief Main module of the retdec-r2plugin.
 * @copyright (c) 2019 Avast Software, licensed under the LGPLv3 license.
 */

#include <algorithm>
#include <cstring>
#include <iostream>
#include <iterator>
#include <mutex>

#include <r_core.h>
#include <retdec/config/config.h>
#include <sstream>

#include <r_util/r_annotated_code.h>

#include "r2plugin/r2cgen.h"
#include "r2plugin/r2info.h"
#include "r2plugin/r2utils.h"

#include "filesystem_wrapper.h"

#define CMD_PREFIX "pdz" /**< Plugin activation command in r2 console.**/

using namespace retdec::r2plugin;

/**
 * @brief Prins help on r2 console.
 */
static void printHelp(const RCore &core)
{
	const char* help[] = {
		"Usage: " CMD_PREFIX, "", "# Native RetDec decompiler plugin.",
		CMD_PREFIX, "", "# Decompile current function with the RetDec decompiler.",
		CMD_PREFIX, "j", "# Dump the current decompiled function as JSON.",
		CMD_PREFIX, "o", "# Decompile current function side by side with offsets.",
		CMD_PREFIX, "*", "# Decompiled code is returned to r2 as a comment.",
		"Environment:", "", "",
		"%RETDEC_PATH" , "", "# Path to the RetDec decompiler script.",
		"%DEC_SAVE_DIR", "", "# Directory to save decompilation into.",
		NULL
	};

	r_cons_cmd_help(help, core.print->flags & R_PRINT_FLAGS_COLOR);
}

/**
 * @brief Provides sanitization of a command path.
 *
 * Purpose of this function is to solve problem when an user
 * specified paths contain spaces. This would result for example in
 * misinterpratation of the program and its args.
 * Sanitization is provided by wrapping the command in double
 * qoutes. This, however, brings new problem -> existing
 * double qoutes must be escaped.
 *
 * Example:
 *  User input: /home/user/"my" dir/retdec-decompiler.py
 *  Fnc output: "/home/user/\"my\" dir/retdec-decompiler.py"
 *
 * @param path Full path of the command.
 */
std::string sanitizePath(const std::string &path)
{
	std::ostringstream str;
	for (char c: path) {
		if (c == '\'')
			str << "'\\\''";
		else
			str << c;
	}

	return "\'"+str.str()+"\'";
}

/**
 * @brief Prepares parameters of a runnable command.
 *
 * Joins parameters as tokens separated with spaces. Each parameter
 * must be properly sanitized before calling this function.
 */
std::string prepareCommandParams(const std::vector<std::string> &params)
{
	FormatUtils fu;
	auto preparedParams = fu.joinTokens(params, " ");

	return preparedParams;
}

/**
 * @brief Preapre command for running.
 *
 * This function is dedicated for preparation of command for running.
 * Right now this function only returns its input on output.
 */
std::string preapreCommand(const std::string &cmd)
{
	return cmd;
}

/**
 * @brief Run specified command, with specified parameters and output redirection.
 *
 * @param cmd      Command to be runned. In case of full path of the executable the path must be sanitized
 *                 and existence of the executable should be verified before calling this function.
 * @param params   Parameters of the command. No sanitization is provided. If a parameter contains spaces
 *                 it will probably be interprated as two parameters.
 * @param redirect File where output will be redirected. No sanitization is provided and existence of file
 *                 is not verified.
 */
void run(const std::string& cmd, const std::vector<std::string> &params, const std::string &redirect)
{
	auto systemCMD = preapreCommand(cmd)
				+" "+prepareCommandParams(params)
				+" > "+redirect;

	if (int exitCode = system(systemCMD.c_str())) {
		throw DecompilationError("decompilation was not successful: exit code: "+std::to_string(exitCode));
	}
}

/**
 * @brief Fetches path of the RetDec decompiler script (retdec-decompiler.py).
 *
 * Decompiler cript is search for in following:
 *   1. Environemnt variable RETDEC_PATH.
 *     - This provides option to dynamically change RetDec's version.
 *   2. During compilation set RETEC_INSTALL_PREFIX.
 *     - This is path where decompiler script will be used when no environment
 *       variable is provided. Typically it is equal to CMAKE_INSTALL_PREFIX,
 *       however, user might provide their own path.
 *
 * @throws DecompilationError If the RetDec decompiler script is not found in
 *                            the specified path (environment, compiled path, ...).
 */
fs::path fetchRetdecPath()
{
	// If user specified environment variable then use it primarily.
	auto userCustomRaw = getenv("RETDEC_PATH");
	std::string userCustom(userCustomRaw != nullptr ? userCustomRaw : "");

	if (userCustom != "") {
		fs::path userCustomPath(userCustom);
		if (!fs::exists(userCustomPath))
			throw DecompilationError("invalid $RETDEC_PATH set: "+userCustom);

		return userCustomPath;
	}

#if defined(RETDEC_INSTALL_PREFIX)
	// If user wanted to install bundled RetDec with retdec-r2plugin.
	auto rddef = fs::path(RETDEC_INSTALL_PREFIX)/"bin"/"retdec-decompiler.py";
	if (fs::exists(rddef))
		return rddef;
#endif

	throw DecompilationError("cannot detect RetDec decompiler script. Please set $RETDEC_PATH to the path of the retdec-decompiler.py script.");
}

/**
 * Fetches the directory for output to be saved to.
 *
 * User can specify DEC_SAVE_DIR environment variable to dynamically
 * customize behavior of this function.
 *
 * If DEC_SAVE_DIR is not specified the temporary direcotry is returned
 * by calling fs::temp_directory_path.
 *
 * @throws DecompilationError In case when no the provided directory does
 *                            not exist or it is not possible to create
 *                            temporary directory DecompilationError is
 *                            thrown.
 */
fs::path getOutDirPath()
{
	std::error_code err;

	auto outDirRaw = getenv("DEC_SAVE_DIR");
	std::string outDir(outDirRaw != nullptr ? outDirRaw : "");
	if (outDir != "") {
		auto outDirPath = fs::path(outDir);
		if (!is_directory(outDirPath, err)) {
			throw DecompilationError("invald $DEC_SAVE_DIR: not a directory: "+outDir);
		}

		return outDirPath;
	}

	auto tmpDir = fs::temp_directory_path(err);

	if (tmpDir.string() == "") {
		// This is a fallback solution for situation when user does
		// not have TMPDIR environment variable set. In this case the
		// standard function `temp_directory_path` seems to not
		// be able to find the /tmp directory and thus return
		// empty string with error code. This was reported
		// to happen only on linux systems with standard /tmp
		// directory and only when this method is called from r2 console.
		tmpDir = fs::path("/tmp");
		if (!is_directory(tmpDir, err)) {
			throw DecompilationError("cannot find a temporary directory on the system. Please specify a temporary directory by setting $TMPDIR, or $DEC_OUT_DIR.");
		}
	}

	return tmpDir;
}

/**
 * @brief Main decompilation method. Uses RetDec to decompile input binary.
 *
 * Decompiles binary on input by configuring and calling RetDec decompiler script.
 *
 * @param binInfo Provides informations gathered from r2 console.
 */
RAnnotatedCode* decompile(const R2InfoProvider &binInfo)
{
	try {
		R2CGenerator outgen;
		auto outDir = getOutDirPath();
		auto config = retdec::config::Config::empty(
				(outDir/"rd_config.json").string());

		auto rdpath = fetchRetdecPath();

		std::string binName = binInfo.fetchFilePath();
		binInfo.fetchFunctionsAndGlobals(config);
		config.generateJsonFile();

		auto fnc = binInfo.fetchCurrentFunction();

		auto decpath = outDir/"rd_dec.json";
		auto outpath = outDir/"rd_out.log";

		std::ostringstream decrange;
		decrange << fnc.getStart() << "-" << fnc.getEnd();

		std::vector<std::string> decparams {
			sanitizePath(binName),
			"--cleanup",
			"--config", sanitizePath(config.getConfigFileName()),
			"-f", "json-human",
			//"--select-decode-only",
			"--select-ranges", decrange.str(),
			"-o", sanitizePath(decpath.string())

		};

		run(sanitizePath(rdpath), decparams, sanitizePath(outpath.string()));
		return outgen.generateOutput(decpath.string());
	}
	catch (const DecompilationError &err) {
		std::cerr << "retdec-r2plugin: " << err.what() << std::endl;
		return nullptr;
	}
}

/**
 * Main function representing plugin behavior. Executes actions
 * based on suffix.
 */
static void _cmd(RCore &core, const char &input)
{
	void (*outputFunction)(RAnnotatedCode *code) = nullptr;

	switch (input) {
		case '\0':
			outputFunction = [](RAnnotatedCode *code) -> void {
				r_core_annotated_code_print(code, nullptr);
			};
			break;

		case 'o':
			outputFunction = [](RAnnotatedCode *code) -> void {
				RVector *offsets = r_annotated_code_line_offsets(code);
				r_core_annotated_code_print(code, offsets);
				r_vector_free(offsets);
			};
			break;

		case 'j':
			outputFunction = r_core_annotated_code_print_json;
			break;

		case '*':
			outputFunction = r_core_annotated_code_print_comment_cmds;
			break;

		default:
			printHelp(core);
			return;
	}

	// This function might be called asynchronously from r2 console (panel menu).
	// this soultion uses lock_guard that will disable other decompilations.
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock (mutex);

	R2InfoProvider binInfo(core);
	auto code = decompile(binInfo);
	if (code == nullptr) {
		return;
	}

	outputFunction(code);
}

/**
 * R2 console registration method. This method is called
 * after each command typed into r2. If the function wants
 * to respond on provided command, provides response and returns true.
 * Activation method for this function is matching prefix of the input.
 *  -> prefix(input) == CMD_PREFIX
 *
 * Otherwise the function must return false which will indicate that
 * other command should be executed.
 */
static int r2retdec_cmd(void *user, const char* input)
{
	RCore& core = *(RCore*)user;

	if (std::strncmp(input, CMD_PREFIX, sizeof(CMD_PREFIX)-1) == 0)
	{
		_cmd(core, input[sizeof(CMD_PREFIX)-1]);
		return true;
	}

	return false;
}

// Structure containing plugin info.
RCorePlugin r_core_plugin_retdec = {
	/* .name = */ "r2retdec",
	/* .desc = */ "RetDec integration",
	/* .license = */ "GPL3",
	/* .author = */ "Avast",
	/* .version = */ "0.1.1",
	/* .call = */ r2retdec_cmd,
	/* .init = */ nullptr,
	/* .fini = */ nullptr
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif

// This will register the r2plugin in r2 console.
R_API RLibStruct radare_plugin = {
	/* .type = */ R_LIB_TYPE_CORE,
	/* .data = */ &r_core_plugin_retdec,
	/* .version = */ R2_VERSION,
	/* .free = */ nullptr,
	/* .pkgname */ "retdec-r2plugin"
};
#endif
