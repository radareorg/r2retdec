/**
 * @file src/r2plugin/core_plugin.cpp
 * @brief Main module of the retdec-r2plugin.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <algorithm>
#include <cstring>
#include <functional>
#include <fstream>
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
fs::path getOutDirPath(const fs::path &suffix = "")
{
	std::error_code err;

	auto outDirRaw = getenv("DEC_SAVE_DIR");
	std::string outDir(outDirRaw != nullptr ? outDirRaw : "");
	if (!outDir.empty()) {
		auto outDirPath = fs::path(outDir);
		if (!is_directory(outDirPath, err)) {
			throw DecompilationError(
				"invald $DEC_SAVE_DIR: not a directory: "
				+outDir
			);
		}

		if (!suffix.empty()) {
			outDirPath /= suffix;
			fs::create_directories(outDirPath);
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

	if (!suffix.empty()) {
		tmpDir /= suffix;
		fs::create_directories(tmpDir);
	}

	return tmpDir;
}

/**
 * @brief Reads hash from file provided as parameter.
 */
std::string loadHashString(const fs::path& cachePath)
{
	std::string cacheFileString;

	if (!fs::is_regular_file(cachePath))
		return "";

	std::ifstream cacheFile(cachePath);

	cacheFile >> cacheFileString;

	cacheFile.close();
	return cacheFileString;
}

/**
 * @brief Constructs hash from RD config.
 */
void constructHash(const retdec::config::Config& config, std::ostream& hash)
{
	// RetDec automatically sets time and date to the JSON
	// config. This is not really wanted as each change of time
	// or date will trigger decompilation. Until RetDec provides
	// API without this we need to manually set time and date
	// to constant string.
	rapidjson::Document d;
	d.Parse(config.generateJsonString());
	rapidjson::Value& time = d["time"];
	rapidjson::Value& date = d["date"];

	time.SetString("removed");
	date.SetString("removed");

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	d.Accept(writer);

	hash << std::hex << std::hash<std::string>{}(buffer.GetString());
}

fs::path getHashPath(const fs::path& configPath)
{
	return fs::path(configPath).replace_filename(".rd_hash");
}

/**
 * @brief Checks if cached files are up to date.
 */
bool usableCacheExists(const retdec::config::Config& config)
{
	fs::path configPath(config.parameters.getOutputConfigFile());

	if (!fs::is_regular_file(configPath))
		return false;

	std::ostringstream currHash;
	constructHash(config, currHash);

	std::string savedHash = loadHashString(getHashPath(configPath));

	return currHash.str() == savedHash;
}

/**
 * @brief Creates file containng hash constructed from RD config.
 */
void createConfigHashFile(const retdec::config::Config& config)
{
	fs::path configPath(config.parameters.getOutputConfigFile());
	fs::path hashPath = getHashPath(configPath);
	std::ofstream hashFile(hashPath);
	constructHash(config, hashFile);
	hashFile.close();
}

/**
 * @brief Tries to find and load default RetDec configuration file.
 *
 * Default configuration is installed with this plugin on default
 * location.
 */
retdec::config::Config loadDefaultConfig()
{
	// Returns plugin home:
	// ~/.local/share/radare2/plugins/
	auto plugdir = r_str_home(R2_HOME_PLUGINS);
	auto plugPath = fs::path(plugdir);
	// plugdir is dynamically allocated.
	free(plugdir);
	// Default config is always installed with the plugin.
	auto configPath = plugPath/"decompiler-config.json";

	// Config must be regular file - exception will be thrown otherwise.
	if (!fs::is_regular_file(configPath)) {
		throw DecompilationError("unable to locate decompiler configuration");
	}

	// Loads configuration from file - also contains default config.
	auto rdConf = retdec::config::Config::fromFile(configPath.string());
	// Paths to the signatures, etc.
	rdConf.parameters.fixRelativePaths(plugPath.string());

	return rdConf;
}

/**
 * @brief Initializes configuration parameters.
 *
 * @param parameters Parameters of a RetDec config.
 * @param binInfo Provides informations gathered from r2 console.
 * @param addr    Address of current function.
 */
void initConfigParameters(
	retdec::config::Parameters& parameters,
	const R2InfoProvider& binInfo,
	ut64 addr)
{
	// Fetch current function
	auto fnc = binInfo.fetchFunction(addr);

	// Fetch binary name -> will be used for caching
	std::string binName = binInfo.fetchFilePath();

	// Create hex from bin name
	std::ostringstream str, hexAddr;
	str << std::hex << std::hash<std::string>{}(binName);
	hexAddr << std::hex << addr;

	// Function is identified as : NAME@HEX_ADDR
	auto outName = fs::path(str.str())/(fnc.getName()+"@0x"+hexAddr.str());

	auto outDir = getOutDirPath(outName);

	auto decpath = outDir/"rd_dec.json";
	auto outpath = outDir/"rd_out.log";
	auto errpath = outDir/"rd_err.log";
	auto outconfig = outDir/"rd_config.json";

	parameters.setInputFile(binInfo.fetchFilePath());
	parameters.setOutputFile(decpath.string());
	parameters.setOutputConfigFile(outconfig.string());
	parameters.setOutputFormat("json-human");
	parameters.selectedRanges.insert(fnc);
	parameters.setIsVerboseOutput(true);
	parameters.setLogFile(outpath.string());
	parameters.setErrFile(errpath.string());
}

/**
 * @brief Main decompilation method. Uses RetDec to decompile input binary.
 *
 * Decompiles binary on input by configuring and calling RetDec decompiler script.
 * Decompiles the binary given by the offset passed addr.
 *
 * Note:
 * This function serves as a fallback for testing and not main
 * feature of this plugin. It is highly possible that this
 * code will be removed in future.
 *
 * @param rdpath  Path to the RetDec decompiler executable.
 * @param config  Configration filled with data ready for RetDec.
 * @param fnc     Function that is decompiled.
 */
RAnnotatedCode* decompileWithScript(
		const fs::path &rdpath,
		const retdec::config::Config& config,
		const retdec::common::Function& fnc)
{
	R2CGenerator outgen;

	std::ostringstream decrange;
	decrange << fnc.getStart() << "-" << fnc.getEnd();

	std::vector<std::string> decparams {
		ce::sanitizePath(config.parameters.getInputFile()),
		"--cleanup",
		"--config", ce::sanitizePath(config.generateJsonFile()),
		"-f", "json-human",
		//"--select-decode-only",
		"--select-ranges", decrange.str(),
		"-o", ce::sanitizePath(config.parameters.getOutputFile())

	};

	ce::execute(
		"",
		ce::sanitizePath(rdpath.string()),
		decparams,
		ce::sanitizePath(config.parameters.getLogFile()),
		ce::sanitizePath(config.parameters.getErrFile())
	);

	return outgen.generateOutput(config.parameters.getOutputFile());
}

/**
 * @brief Main decompilation method. Uses RetDec to decompile input binary.
 *
 * Decompiles binary on input by configuring and calling RetDec decompiler executable.
 * @param binInfo Provides informations gathered from r2 console.
 * @param addr    Address of a function to be decompiled.
 */
std::pair<RAnnotatedCode*, retdec::config::Config> decompile(const R2InfoProvider &binInfo, ut64 addr, bool useCache = true, bool fetchR2Data = true)
{
	try {
		auto config = loadDefaultConfig();

		if (fetchR2Data) {
			binInfo.fetchFunctionsAndGlobals(config);
		}

		initConfigParameters(config.parameters, binInfo, addr);

		if (useCache && usableCacheExists(config)) {
			R2CGenerator outgen;
			return {outgen.generateOutput(config.parameters.getOutputFile()), config};
		}
		else {
			config.generateJsonFile();
			createConfigHashFile(config);
		}

		if (auto rdpath = checkCustomRetDecPath()) {
			auto fnc = binInfo.fetchFunction(addr);
			return {decompileWithScript(*rdpath, config, fnc), config};
		}

		if (auto rc = retdec::decompile(config)) {
			throw DecompilationError(
				"decompliation ended with error code "
				+ std::to_string(rc) +
				"for more details check " + config.parameters.getErrFile()
			);
		}

		R2CGenerator outgen;
		return {outgen.generateOutput(config.parameters.getOutputFile()), config};
	}
	catch (const std::exception &err) {
		std::cerr << "retdec-r2plugin: decompilation was not successful: " << err.what() << std::endl;
	}
	catch (...) {
		std::cerr << "retdec-r2plugin: unkown decompilation error" << std::endl;
	}

	return {nullptr, retdec::config::Config::empty()};
}

/**
 * This function is to get RAnnotatedCode to pass it to Cutter's decompiler widget.
 */
R_API RAnnotatedCode* decompile(RCore *core, ut64 addr){
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock (mutex);

	R2InfoProvider binInfo(*core);
	auto [code, _] = decompile(binInfo, addr);
	return code;
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
	auto [code, config] = decompile(binInfo, core.offset);
	if (code == nullptr || outputFunction == nullptr) {
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
