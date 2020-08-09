#pragma once

#include "r2plugin/console/console.h"

namespace retdec {
namespace r2plugin {

/**
 * Provides and implements Data Analysis console interface
 * that is shown as pdza_ command in r2.
 */
class DataAnalysisConsole: public Console {
protected:
	/// Protected constructor. DataAnalysisConsole is meant to be used as singleton.
	DataAnalysisConsole();

public:
	/// Calls handle method of singleton.
	static bool handleCommand(const std::string& commad, const R2Database& info);

	/// Representation of pdza command.
	static Console::Command AnalyzeRange;

	/// Representation of pdzaa command.
	static Console::Command AnalyzeWholeBinary;

private:
	/// Implementation of pdza command.
	static bool analyzeRange(const std::string&, const R2Database& info);

	/// Implementation of pdzaa command.
	static bool analyzeWholeBinary(const std::string&, const R2Database& info);

private:
	/// Helper method. Parses arguments of pdza commnad.
	static common::AddressRange parseRange(const std::string& range);

private:
	/// Singleton.
	static DataAnalysisConsole console;
};

};
};
