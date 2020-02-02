/**
 * @file src/r2utils.cpp
 * @brief Specific output format utilities.
 * @copyright (c) 2019 Avast Software, licensed under the LGPLv3 license.
 */

#include <regex>
#include <sstream>

#include "r2info.h"
#include "r2utils.h"

using namespace retdec::r2plugin;

const std::map<const std::string, const std::string> FormatUtils::_primitives {
	{"void", "void"},
	{"char", "i8"},
	{"short", "i16"},
	{"int", "i32"},
	{"long", "i64"},
	{"size_t", "i64"},
	{"gid_t", "i32"},
	{"uid_t", "i32"},
	{"pid_t", "i32"},

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

const std::vector<std::string> FormatUtils::_typeKeywords = {
	"const",
	"struct",
	"unsigned",
	"signed"
};

const std::string FormatUtils::joinTokens(const std::vector<std::string> &tokens, const std::string &delim) const
{
	if (tokens.empty()) {
		return "";
	}

	std::ostringstream finalstr;
	std::copy(tokens.begin(), tokens.end()-1,
		   std::ostream_iterator<std::string>(finalstr, delim.c_str()));

	return finalstr.str()+tokens.back();
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

std::string FormatUtils::stripName(const std::string &name) const
{
	static const std::vector r2Prefix = {"sym.", "fcn.", "imp.", "__isoc99_"};

	std::string_view v = name;
	for (auto px: r2Prefix) {
		if (v.length() <= std::strlen(px))
			continue;

		if (v.compare(0, std::strlen(px), px) == 0)
			v.remove_prefix(std::strlen(px));
	}

	return std::string(v);
}

const std::string FormatUtils::convertTypeToLlvm(const std::string &ctype) const
{
	static const std::vector<char> structInternals = {'{', ',', '}'}; 

	if (_primitives.count(ctype)) {
		return _primitives.at(ctype);
	}

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
				token) != _typeKeywords.end()) {
			token = typeTokens.front();
			typeTokens.erase(typeTokens.begin());
		}

		if (token.length() == 1 && std::find(
					structInternals.begin(),
					structInternals.end(),
					token[0]) != structInternals.end()) {
			converted.push_back(token);
			continue;
		}

		if (_primitives.count(token)) {
			converted.push_back(_primitives.at(token));
			continue;
		}

		std::smatch cm;
		if (std::regex_match(token, cm, std::regex("([^*]+)([*]+)"))) {
			if (cm.size() != 2) {
				throw DecompilationError("illegal state");
			}
			converted.push_back(cm[0]);
			converted.push_back(cm[1]);
			continue;
		}

		if (std::regex_match(token, std::regex("[*]+"))) {
			converted.push_back(token);
			continue;
		}
	
		// TODO: this method might return definition of arrays in future.

		auto typeDefinition = getTypeDefinition(token);
		if (typeDefinition == "") {
			// TODO: throw?
			return "void";
		}

		if (std::regex_match(typeDefinition, cm, std::regex("[{](.*)[}]"))) {
			if (cm.size() != 1) {
				throw DecompilationError("illegal state");
			}
			// Push end token
			typeTokens.insert(typeTokens.begin(), "}");
			
			// In C structs declarations elements are separated by ';'.
			std::string strElems(cm[0]);
			strElems.erase(std::remove(strElems.begin(), strElems.end(), ' '), strElems.end());
			auto structElemTokens = splitTokens(strElems, ';');
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
		return "void";
	}

        return joinTokens(converted);
}

const std::string FormatUtils::getTypeDefinition(const std::string &token) const
{
	return "void";
}
