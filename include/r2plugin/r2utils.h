/**
 * @file include/r2plugin/r2utils.h
 * @brief Specific output format utilities.
 * @copyright (c) 2019 Avast Software, licensed under the LGPLv3 license.
 */

#ifndef RETDEC_R2PLUGIN_R2UTILS_H
#define RETDEC_R2PLUGIN_R2UTILS_H

#include <map>
#include <string>
#include <vector>

#include <r_core.h>

namespace retdec {
namespace r2plugin {

class FormatUtils {
private:
	~FormatUtils();

public:
	static const std::string convertTypeToLlvm(const std::string &ctype);

	static const std::string joinTokens(
			const std::vector<std::string> &tokens,
			const std::string &delim = " ");
	static std::vector<std::string> splitTokens(
			const std::string &type,
			char delim = ' ');

	static std::string stripName(const std::string &name);

protected:
	static const std::string getTypeDefinition(const std::string &token);

private:
	static const std::map<const std::string, const std::string> _primitives;
	static const std::vector<std::string> _typeKeywords;
};

}
}

#endif /*RETDEC_R2PLUGIN_R2UTILS_H*/
