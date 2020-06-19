/**
 * @file src/r2plugin/core_plugin.cpp
 * @brief Main module of the retdec-r2plugin.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <algorithm>
#include <cstring>
#include <iostream>
#include <iterator>
#include <mutex>

#include <r_core.h>
#include <retdec/retdec/retdec.h>
#include <retdec/utils/binary_path.h>
#include <retdec/config/config.h>
#include <retdec/config/parameters.h>
#include <sstream>

#include "r2plugin/cmd_exec.h"
#include "r2plugin/r2retdec.h"
#include "r2plugin/r2cgen.h"
#include "r2plugin/r2utils.h"

#include "filesystem_wrapper.h"

#define CMD_PREFIX "pdz" /**< Plugin activation command in r2 console.**/

using namespace retdec::r2plugin;
using ce = retdec::r2plugin::CmdExec;
using fu = retdec::r2plugin::FormatUtils;

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
		"%RETDEC_PATH" , "", "# Path to the RetDec decompiler executable.",
		"%DEC_SAVE_DIR", "", "# Directory to save decompilation into.",
		NULL
	};

	r_cons_cmd_help(help, core.print->flags & R_PRINT_FLAGS_COLOR);
}

/**
 * @brief Fetches path of the RetDec decompiler executable (retdec-decompiler.py).
 *
 * Decompiler cript is search for in following:
 *   1. Environemnt variable RETDEC_PATH.
 *     - This provides option to dynamically change RetDec's version.
 *   2. During compilation set RETEC_INSTALL_PREFIX.
 *     - This is path where decompiler executable will be used when no environment
 *       variable is provided. Typically it is equal to CMAKE_INSTALL_PREFIX,
 *       however, user might provide their own path.
 *
 * @throws DecompilationError If the RetDec decompiler executable is not found in
 *                            the specified path (environment, compiled path, ...).
 */
std::optional<fs::path> checkCustomRetDecPath()
{
	// If user specified environment variable then use it primarily.
	auto userCustomRaw = getenv("RETDEC_PATH");
	std::string userCustom(userCustomRaw != nullptr ? userCustomRaw : "");

	if (userCustom != "") {
		fs::path userCustomPath(userCustom);
		if (!fs::is_regular_file(userCustomPath))
			throw DecompilationError("invalid $RETDEC_PATH set: "+userCustom);

		return userCustomPath;
	}

	return {};
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
			throw DecompilationError(
				"invald $DEC_SAVE_DIR: not a directory: "
				+outDir
			);
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
			throw DecompilationError(
				"cannot find a temporary directory on the system. "
				"Please specify a temporary directory by setting "
				"$TMPDIR, or $DEC_OUT_DIR."
			);
		}
	}

	return tmpDir;
}

/**
 * @brief Main decompilation method. Uses RetDec to decompile input binary.
 *
 * Decompiles binary on input by configuring and calling RetDec decompiler script.
 * Decompiles the binary given by the offset passed addr.
 * 
 * @param binInfo Provides informations gathered from r2 console.
 * @param addr Decompiles the function at this offset.
 */
RAnnotatedCode* decompileWithScript(
		const fs::path &rdpath,
		const R2InfoProvider &binInfo,
		ut64 addr)
{
		R2CGenerator outgen;
		auto outDir = getOutDirPath();
		auto config = retdec::config::Config::empty();

		std::string binName = binInfo.fetchFilePath();
		binInfo.fetchFunctionsAndGlobals(config);

		auto fnc = binInfo.fetchCurrentFunction(addr);

		auto decpath = outDir/"rd_dec.json";
		auto outpath = outDir/"rd_out.log";
		auto errpath = outDir/"rd_err.log";
		auto outconfig = outDir/"rd_config.json";

		config.parameters.setOutputConfigFile(outconfig);

		config.generateJsonFile();

		std::ostringstream decrange;
		decrange << fnc.getStart() << "-" << fnc.getEnd();

		std::vector<std::string> decparams {
			ce::sanitizePath(binName),
			"--cleanup",
			"--config", ce::sanitizePath(config.generateJsonFile()),
			"-f", "json-human",
			//"--select-decode-only",
			"--select-ranges", decrange.str(),
			"-o", ce::sanitizePath(decpath.string())

		};

		ce::execute(
			"",
			ce::sanitizePath(rdpath.string()),
			decparams,
			ce::sanitizePath(outpath.string()),
			ce::sanitizePath(errpath.string())
		);

		return outgen.generateOutput(decpath.string());
}

retdec::config::Config loadDefaultConfig()
{
// TODO: First Check Installed Path

// Fallback to default Radare2 Plugin directory
	auto plugdir = r_str_home (R2_HOME_PLUGINS);
	auto plugPath = fs::path(plugdir); free(plugdir);
	auto configPath = plugPath/"decompiler-config.json";

	if (!fs::exists(configPath)) {
		throw DecompilationError("unable to locate decompiler configuration");
	}

	auto rdConf = retdec::config::Config::fromFile(configPath);
	rdConf.parameters.fixRelativePaths(plugPath);

	return rdConf;
}

/**
 * @brief Main decompilation method. Uses RetDec to decompile input binary.
 *
 * Decompiles binary on input by configuring and calling RetDec decompiler executable.
 *
 * TODO:
 *  - merge similiar code from decompileWithScript
 *  - return error messages instead of printing them
 * @param binInfo Provides informations gathered from r2 console.
 */
RAnnotatedCode* decompile(const R2InfoProvider &binInfo, ut64 addr)
{
	try {
		if (auto rdpath = checkCustomRetDecPath()) {
			return decompileWithScript(*rdpath, binInfo, addr);
		}

		auto outDir = getOutDirPath();
		auto config = loadDefaultConfig();

		std::string binName = binInfo.fetchFilePath();
		binInfo.fetchFunctionsAndGlobals(config);

		auto fnc = binInfo.fetchCurrentFunction(addr);

		auto decpath = outDir/"rd_dec.json";
		auto outpath = outDir/"rd_out.log";
		auto errpath = outDir/"rd_err.log";
		auto outconfig = outDir/"rd_config.json";

		config.parameters.setInputFile(binName);
		config.parameters.setOutputFile(decpath.string());
		config.parameters.setOutputConfigFile(outconfig);
		config.parameters.setOutputFormat("json-human");
		config.parameters.selectedRanges.insert(fnc);
		config.parameters.setIsVerboseOutput(false);
		//config.parameters.setIsSelectedDecodeOnly(true);

		config.generateJsonFile();

		if (auto rc = retdec::decompile(config)) {
			throw DecompilationError(
				"decompliation ended with error code "
				+ std::to_string(rc) +
				"for more details check " + errpath.string()
			);
		}

		R2CGenerator outgen;
		return outgen.generateOutput(decpath.string());
	}
	catch (const std::exception &err) {
		std::cerr << "retdec-r2plugin: decompilation was not successful: " << err.what() << std::endl;
	}
	catch (...) {
		std::cerr << "retdec-r2plugin: unkown decompilation error" << std::endl;
	}

	return nullptr;
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
	auto code = decompile(binInfo, core.offset);
	if (code == nullptr) {
		return;
	}

	outputFunction(code);
}

/**
 * This function is to get RAnnotatedCode to pass it to Cutter's decompiler widget.
 */
RAnnotatedCode* r2retdec_decompile_annotated_code(RCore *core, ut64 addr){
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock (mutex);

	R2InfoProvider binInfo(*core);
	return decompile(binInfo, addr);
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
	/* .version = */ "0.1.2",
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
