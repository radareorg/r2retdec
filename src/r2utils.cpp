#include <regex>
#include <sstream>

#include "r2info.h"
#include "r2utils.h"

using namespace retdec::r2plugin;

std::map<const std::string, const std::string> FormatUtils::_primitives {
	{"void", "void"},
	{"char", "i8"},
	{"short", "i16"},
	{"int", "i32"},
	{"long", "i64"},
	{"size_t", "i64"},

	{"int8_t", "i8"},
	{"int16_t", "i16"},
	{"int32_t", "i32"},
	{"int64_t", "i64"},

	{"uint8_t", "i8"},
	{"uint16_t", "i16"},
	{"uint32_t", "i32"},
	{"uint64_t", "i64"},

	{"float", "float"},
	{"double", "double"}
};

std::vector<std::string> FormatUtils::_typeKeywords = {
	"const",
	"struct",
	"unsigned",
	"signed"
};

const std::string FormatUtils::joinTokens(const std::vector<std::string> &tokens, char delim) const
{
	char delimStr[] = {delim ,0};
	std::ostringstream finalstr;
	std::copy(tokens.begin(), tokens.end(),
		   std::ostream_iterator<std::string>(finalstr, delimStr));

	return finalstr.str();
}

std::vector<std::string> FormatUtils::splitTokens(const std::string &type, char delim) const
{
	std::vector<std::string> tokensResult;
	std::istringstream iss(type);
	std::string token;

	while (getline(iss, token, delim)) {
		    tokensResult.push_back(token);
	}

	return tokensResult;
}

const std::string FormatUtils::convertTypeToLlvm(const std::string &ctype) const
{
	static const std::vector<char> structInternals = {'{', ',', '}'}; 

	if (_primitives.count(ctype))
		return _primitives[ctype];

        // struct a {unsigned char*, unsigned char**}
        //    -> [struct, unsigned, char, *, unsigned, char, **]
	//
	// const int
	// [const, int]
	std::vector<std::string> typeTokens = splitTokens(ctype);

        std::vector<std::string> converted{};

        while (!typeTokens.empty()) {
		auto token = typeTokens.front();
		typeTokens.erase(typeTokens.begin());
		if (std::find(_typeKeywords.begin(),
				_typeKeywords.end(),
				ctype) != _typeKeywords.end()) {
			token = typeTokens.front();
			typeTokens.erase(typeTokens.begin());
		}

		if (token.size() == 1 && std::find(
					structInternals.begin(),
					structInternals.end(),
					token[0]) != structInternals.end()) {
			converted.push_back(token);
			continue;
		}

		if (_primitives.count(ctype)) {
			converted.push_back(_primitives.at(token));
			continue;
		}

		if (std::regex_match(token, std::regex("\\*+"))) {
			converted.push_back(token);
			continue;
		}
	
		// TODO: this method might return definition of arrays in future.

		std::vector<std::string> save(typeTokens);
		auto typeDefinition = getTypeDefinition(token);
		if (typeDefinition != "") {
			// TODO: throw?
			return "void";
		}

		std::smatch cm;
		if (std::regex_match(typeDefinition, cm, std::regex("{(.*)}"))) {
			if (cm.size() != 1) {
				throw DecompilationError("illegal state");
			}
			// Push end token
			typeTokens.insert(typeTokens.begin(), "}");
			
			// In C structs declarations elements are separated by ';'.
			auto structElemTokens = splitTokens(cm[0], ';');
			// pop empty string
			structElemTokens.pop_back();
			
			for (auto it = structElemTokens.rbegin();
					it != structElemTokens.rend(); it++) {
				typeTokens.insert(typeTokens.begin(), convertTypeToLlvm(*it));
				typeTokens.insert(typeTokens.begin(), ",");
			}

			typeTokens.erase(typeTokens.begin());
			// Push begin token
			typeTokens.push_back("{");
		}
	}

        return joinTokens(converted);
}

const std::string FormatUtils::getTypeDefinition(const std::string &token) const
{
	return "void";
}
