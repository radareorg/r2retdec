#include <cstring>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <mutex>

#include <r_core.h>
#include <retdec/config/config.h>

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
		NULL
	};

	r_cons_cmd_help(help, core.print->flags & R_PRINT_FLAGS_COLOR);
}

void run(const std::vector<std::string> cmd)
{
	const char* const delim = " ";

	std::ostringstream finalcmd;
	std::copy(cmd.begin(), cmd.end(),
		   std::ostream_iterator<std::string>(finalcmd, delim));

	system(finalcmd.str().c_str());
}

std::string fetchRetdecPath()
{
	auto rdpRaw = getenv("RETDEC_PATH");
	std::string rdpath(rdpRaw != nullptr ? rdpRaw : "");
	
	if (rdpath == "") {
		// TODO: default path to look at
		throw DecompilationError("missing path to RetDec decompilation script");
	}

	return rdpath;
}

RAnnotatedCode* decompile(const R2InfoProvider &binInfo)
{
	try {
		R2CGenerator outgen;
		auto config = retdec::config::Config::empty(
				(fs::temp_directory_path()/"rd_config.json").string());

		auto rdpath = fetchRetdecPath();

		std::string binName = binInfo.fetchFilePath();
		binInfo.fetchFunctions(config);
		config.generateJsonFile();

		auto fnc = binInfo.fetchCurrentFunction();
		
		auto decpath = fs::temp_directory_path()/"rd_dec.json";
		auto outpath = fs::temp_directory_path()/"rd_out.log";

		std::ostringstream decrange;
		decrange << fnc.getStartLine() << "-" << fnc.getEndLine();

		std::vector<std::string> deccmd {
			rdpath,
			binName,
			"--cleanup",
			"--config", config.getConfigFileName(),
			"-f", "json-human",
			"--select-ranges", decrange.str(),
			"-o", decpath.string(),
			">", outpath.string()
		};

		run(deccmd);
		return outgen.generateOutput(decpath.string());
	}
	catch (const DecompilationError err) {
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
