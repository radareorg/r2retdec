#include <algorithm>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <mutex>

#include <r_core.h>
#include <retdec/config/config.h>
#include <sstream>

#include "AnnotatedCode.h"
#include "r2cgen.h"
#include "r2info.h"
#include "r2utils.h"

#define CMD_PREFIX "pdz"

namespace fs = std::filesystem;
using namespace retdec::r2plugin;

static void printHelp(const RCore &core)
{
	const char* help[] = {
		"Usage: " CMD_PREFIX, "", "# Native RetDec decompiler plugin.",
		CMD_PREFIX, "", "# Decompile current function with the RetDec decompiler.",
		CMD_PREFIX, "j", "# Dump the current decompiled function as JSON",
		CMD_PREFIX, "o", "# Decompile current function side by side with offsets.",
		CMD_PREFIX, "*", "# Decompiled code is returned to r2 as comment.",
		"Environment:", "", "",
		"%RETDEC_PATH" , "", "# Path to the RetDec decompiler script.",
		"%DEC_SAVE_DIR", "", "# Directory to save decompilation into.",
		NULL
	};

	r_cons_cmd_help(help, core.print->flags & R_PRINT_FLAGS_COLOR);
}

std::string formatPathForCommand(const std::string &path)
{
	std::ostringstream str;
	for (char c: path) {
		if (c == '"')
			str << "\\\"";
		else
			str << c;
	}

	return "\""+str.str()+"\"";
}

std::string prepareParams(const std::vector<std::string> &params)
{
	FormatUtils fu;
	auto preparedParams = fu.joinTokens(params, " ");

	return preparedParams;
}

std::string preapreCommand(const std::string &cmd)
{
	return cmd;
}

void run(const std::string& cmd, const std::vector<std::string> &params, const std::string &redirect)
{
	auto systemCMD = preapreCommand(cmd)
				+" "+prepareParams(params)
				+" > "+redirect;

	system(systemCMD.c_str());
}

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

RAnnotatedCode* decompile(const R2InfoProvider &binInfo)
{
	try {
		R2CGenerator outgen;
		auto outDir = getOutDirPath();
		auto config = retdec::config::Config::empty(
				(outDir/"rd_config.json").string());

		auto rdpath = fetchRetdecPath();

		std::string binName = binInfo.fetchFilePath();
		binInfo.fetchFunctions(config);
		config.generateJsonFile();

		auto fnc = binInfo.fetchCurrentFunction();
		
		auto decpath = outDir/"rd_dec.json";
		auto outpath = outDir/"rd_out.log";

		std::ostringstream decrange;
		decrange << fnc.getStart() << "-" << fnc.getEnd();

		std::vector<std::string> decparams {
			binName,
			"--cleanup",
			"--config", formatPathForCommand(config.getConfigFileName()),
			"-f", "json-human",
			//"--select-decode-only",
			"--select-ranges", decrange.str(),
			"-o", formatPathForCommand(decpath.string())

		};

		run(formatPathForCommand(rdpath), decparams, formatPathForCommand(outpath.string()));
		return outgen.generateOutput(decpath.string());
	}
	catch (const DecompilationError &err) {
		std::cerr << "retdec-r2plugin: " << err.what() << std::endl;
		return nullptr;
	}
}

static void _cmd(RCore &core, const char &input)
{
	void (*outputFunction)(RAnnotatedCode *code) = nullptr;

	switch (input) {
		case '\0':
			outputFunction = [](RAnnotatedCode *code) -> void {
				r_annotated_code_print(code, nullptr);
			};
			break;

		case 'o':
			outputFunction = [](RAnnotatedCode *code) -> void {
				RVector *offsets = r_annotated_code_line_offsets(code);
				r_annotated_code_print(code, offsets);
				r_vector_free(offsets);
			};
			break;

		case 'j':
			outputFunction = r_annotated_code_print_json;
			break;

		case '*':
			outputFunction = r_annotated_code_print_comment_cmds;
			break;

		default:
			printHelp(core);
			return;
	}

	static std::mutex mutex;
	std::lock_guard<std::mutex> lock (mutex);

	R2InfoProvider binInfo(core);
	auto code = decompile(binInfo);
	if (code == nullptr) {
		return;
	}
	
	outputFunction(code);
}

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

RCorePlugin r_core_plugin_retdec = {
	/* .name = */ "r2retdec",
	/* .desc = */ "RetDec integration",
	/* .license = */ "GPL3",
	/* .author = */ "xkubov",
	/* .version = */ nullptr,
	/* .call = */ r2retdec_cmd,
	/* .init = */ nullptr,
	/* .fini = */ nullptr
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif
R_API RLibStruct radare_plugin = {
	/* .type = */ R_LIB_TYPE_CORE,
	/* .data = */ &r_core_plugin_retdec,
	/* .version = */ R2_VERSION,
	/* .free = */ nullptr,
	/* .pkgname */ "retdec-r2plugin"
};
#endif
