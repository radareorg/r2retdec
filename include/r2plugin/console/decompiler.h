#pragma once

#include "r2plugin/console/console.h"
#include "r2plugin/r2retdec.h"

namespace retdec {
namespace r2plugin {

class DecompilerConsole: public Console {
protected:
	DecompilerConsole();

public:
	static bool handleCommand(const std::string& commad, const R2InfoProvider& info);

public:
	static const Console::Command DecompileCurrent;
	static const Console::Command DecompileWithOffsetsCurrent;
	static const Console::Command DecompileJsonCurrent;
	static const Console::Command DecompileCommentCurrent;
	static const Console::Command DecompilerDataAnalysis;
	static const Console::Command ShowUsedEnvironment;

private:
	static bool decompileCurrent(const std::string&, const R2InfoProvider& info);
	static bool decompileJsonCurrent(const std::string&, const R2InfoProvider& info);
	static bool decompileWithOffsetsCurrent(const std::string&, const R2InfoProvider& info);
	static bool decompileCommentCurrent(const std::string&, const R2InfoProvider& info);
	static config::Config createConsoleConfig(const R2InfoProvider& binInfo);
	static bool showEnvironment(const std::string&, const R2InfoProvider&);

private:
	static DecompilerConsole console;
};

};
};
