#include "r2plugin/console/decompiler.h"
#include "r2plugin/console/data_analysis.h"

#define CMD_PREFIX "pdz" /**< Plugin activation command in r2 console.**/

namespace retdec {
namespace r2plugin {

DecompilerConsole DecompilerConsole::console;

DecompilerConsole::DecompilerConsole(): Console(
	"pdz",
	"Native RetDec decompiler plugin.",
	{
		{"", DecompileCurrent},
		{"o", DecompileWithOffsetsCurrent},
		{"j", DecompileJsonCurrent},
		{"a", DecompilerDataAnalysis},
		{"*", DecompileWithOffsetsCurrent}
	})
{
}

const Console::Command DecompilerConsole::DecompileCurrent = {
	"Show decompilation result of current function.",
	DecompilerConsole::decompileCurrent
};

const Console::Command DecompilerConsole::DecompileWithOffsetsCurrent = {
	"Show current decompiled function side by side with offsets.",
	DecompilerConsole::decompileWithOffsetsCurrent
};

const Console::Command DecompilerConsole::DecompileJsonCurrent = {
	"Dump current decompiled function as JSON.",
	DecompilerConsole::decompileJsonCurrent
};

const Console::Command DecompilerConsole::DecompileCommentCurrent = {
	"Return decompilation of current function to r2 as comment.",
	DecompilerConsole::decompileCommentCurrent
};

const Console::Command DecompilerConsole::DecompilerDataAnalysis = {
	"Run RetDec analysis.",
	DataAnalysisConsole::handleCommand,
	true
};

config::Config DecompilerConsole::createConsoleConfig(const R2InfoProvider& binInfo)
{
	auto fnc = binInfo.fetchSeekedFunction();
	auto config = createConfig(binInfo, cacheName(fnc));
	config.parameters.selectedRanges.insert(fnc);
	config.parameters.setIsSelectedDecodeOnly(true);

	binInfo.fetchFunctionsAndGlobals(config);

	return config;
}

bool DecompilerConsole::handleCommand(const std::string& command, const R2InfoProvider& info)
{
	return DecompilerConsole::console.handle(command, info);
}

bool DecompilerConsole::decompileCurrent(const std::string&, const R2InfoProvider& binInfo)
{
	auto config = createConsoleConfig(binInfo);

	auto [code, _] = decompile(config, true);
	if (code == nullptr)
		return false;

	r_core_annotated_code_print(code, nullptr);
	return true;
}

bool DecompilerConsole::decompileWithOffsetsCurrent(const std::string&, const R2InfoProvider& binInfo)
{
	auto config = createConsoleConfig(binInfo);

	auto [code, _] = decompile(config, true);
	if (code == nullptr)
		return false;

	RVector *offsets = r_annotated_code_line_offsets(code);
	r_core_annotated_code_print(code, offsets);
	r_vector_free(offsets);

	return true;
}


bool DecompilerConsole::decompileJsonCurrent(const std::string&, const R2InfoProvider& binInfo)
{
	auto config = createConsoleConfig(binInfo);

	auto [code, _] = decompile(config, true);
	if (code == nullptr)
		return false;

	r_core_annotated_code_print_json(code);
	return true;
}

bool DecompilerConsole::decompileCommentCurrent(const std::string&, const R2InfoProvider& binInfo)
{
	auto config = createConsoleConfig(binInfo);

	auto [code, _] = decompile(config, true);
	if (code == nullptr)
		return false;

	r_core_annotated_code_print_comment_cmds(code);
	return true;
}

}
}
