/**
 * @file src/r2plugin/console/data_analysis.cpp
 * @brief Implementation of data analysis console (pdza_).
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <iostream>
#include <regex>

#include "r2plugin/r2retdec.h"
#include "r2plugin/console/data_analysis.h"

namespace retdec {
namespace r2plugin {

DataAnalysisConsole DataAnalysisConsole::console;

Console::Command DataAnalysisConsole::AnalyzeRange{
	"Analyze and import functions at specified range. "
	"Defualt range is range of currently seeked function.",
	analyzeRange,
	false,
	"[start-end]"
};

Console::Command DataAnalysisConsole::AnalyzeWholeBinary{
	"Analyze and import all functions.",
	analyzeWholeBinary
};

DataAnalysisConsole::DataAnalysisConsole(): Console(
	"pdza",
	"Run RetDec analysis.",
	{
		{"", AnalyzeRange},
		{"a", AnalyzeWholeBinary}
	})
{
}

bool DataAnalysisConsole::handleCommand(const std::string& command, const R2Database& info)
{
	return DataAnalysisConsole::console.handle(command, info);
}

common::AddressRange DataAnalysisConsole::parseRange(const std::string& range)
{
	std::smatch match;
	std::regex rangeRegex("(0x)?([0-9a-fA-F][0-9a-fA-F]*)(?:-|  *)(0x)?([0-9a-fA-F][0-9a-fA-F]*)");
	
	if (!std::regex_match(range, match, rangeRegex))
		throw DecompilationError("Invalid range: "+range);

	char* end = nullptr;
	size_t base = match[1].str() == "0x" ? 16 : 10;
	auto beginRange = std::strtol(match[2].str().c_str(), &end, base);
	if (end == nullptr || *end != '\0')
		throw DecompilationError("Invalid number: "+match[2].str());

	base = match[3].str() == "0x" ? 16 : 10;
	auto endRange = std::strtol(match[4].str().c_str(), &end, base);
	if (end == nullptr || *end != '\0')
		throw DecompilationError("Invalid number: "+match[4].str());

	return common::AddressRange(beginRange, endRange);
}

common::AddressRange defaultAnalysisRange(const common::Address& start)
{
	// Magic constant 2000 should be more cleverly set.
	return {start, start+2000};
}

/**
 * Runs decompilation on range of currently seeked function. Optional argument is 
 */
bool DataAnalysisConsole::analyzeRange(const std::string& command, const R2Database& binInfo)
{
	std::string cache = "";

	common::AddressRange toAnalyze;
	std::string params;
	auto space = std::find(command.begin(), command.end(), ' ');
	if (space != command.end()) {
		params = std::string(std::next(space), command.end());
		toAnalyze = parseRange(params);
	}
	else {
		try {
			auto fnc = binInfo.fetchSeekedFunction();
			toAnalyze = fnc;
			if (fnc.getSize() == 0)
				toAnalyze = defaultAnalysisRange(fnc.getStart());

			cache = cacheName(fnc);
		} catch (DecompilationError){
			toAnalyze = defaultAnalysisRange(binInfo.seekedAddress());
		}
	}

	auto config = createConfig(binInfo, cache);

	// TODO:
	// RetDec experiences off by one error.
	// This should be noted in RetDec issue.
	if (toAnalyze.getStart() != 0)
		toAnalyze.setStart(toAnalyze.getStart()-1);

	config.parameters.selectedRanges.insert(toAnalyze);
	config.parameters.setIsSelectedDecodeOnly(true);

	auto [code, _] = decompile(config, false);
	if (code == nullptr)
		return false;

	binInfo.setFunctions(config);

	return true;
}

bool DataAnalysisConsole::analyzeWholeBinary(const std::string&, const R2Database& binInfo)
{
	auto config = createConfig(binInfo, "whole");

	auto [code, _] = decompile(config, false);
	if (code == nullptr)
		return false;

	// r_core_annotated_code_print(code, nullptr);
	binInfo.setFunctions(config);

	return true;
}

}
}
