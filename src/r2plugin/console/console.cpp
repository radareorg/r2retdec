#include <iostream>
#include <regex>

#include "r2plugin/console/console.h"

namespace retdec {
namespace r2plugin {

Console::Console(
	const std::string& base,
	const std::string& about,
	const std::vector<Console::NamedCommand>& cmds):
		_base(base),
		_about(about),
		_callbacks(cmds.begin(), cmds.end())
{
}

bool Console::handle(const std::string& cmd, const R2Database& info)
{
	if (cmd.compare(0, _base.length(), _base, 0, _base.length()) != 0)
		return false;

	auto prefixEnd = std::next(cmd.begin(), _base.length());
	auto suffixBegin = prefixEnd == cmd.end() ? cmd.end() : std::next(prefixEnd);

	auto suffix = std::string(prefixEnd, suffixBegin);
	auto space = std::find(suffix.begin(), suffix.end(), ' ');
	auto subcmd = std::string(suffix.begin(), space);

	auto it = _callbacks.find(subcmd);
	if (it == _callbacks.end()) {
		printHelp(info.core());
		return true;
	}

	if (auto callback = it->second.execute)
		callback(cmd, info);

	return true;
}

bool Console::printHelp(const RCore& core) const
{
	std::vector<std::string> help;
	help.push_back("Usage: "+_base);
	help.push_back("");
	help.push_back(_about.empty()? "" : "# "+_about);
	for (auto [k, v]: _callbacks) {
		help.push_back(_base+k);
		std::string extra = "";
		if (v.extra)
			extra += "[?]";
		if (!v.parameters.empty())
			extra += " "+v.parameters;
		help.push_back(extra);
		help.push_back("# "+v.help);
	}

	std::vector<const char*> helpRaw;
	for (const std::string& s: help) {
		helpRaw.push_back(s.c_str());
	}

	helpRaw.push_back(nullptr);

	r_cons_cmd_help(helpRaw.data(), core.print->flags & R_PRINT_FLAGS_COLOR);
	return true;
}

}
}
