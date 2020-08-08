#pragma once

#include "r2plugin/console/console.h"

namespace retdec {
namespace r2plugin {

class DataAnalysisConsole: public Console {
protected:
	DataAnalysisConsole();

public:
	static bool handleCommand(const std::string& commad, const R2InfoProvider& info);
	static Console::Command AnalyzeRange;
	static Console::Command AnalyzeWholeBinary;

private:
	static bool analyzeRange(const std::string&, const R2InfoProvider& info);
	static bool analyzeWholeBinary(const std::string&, const R2InfoProvider& info);

private:
	static common::AddressRange parseRange(const std::string& range);

private:
	static DataAnalysisConsole console;
};

};
};
