/**
 * @file src/r2plugin/r2utils.cpp
 * @brief Specific output format utilities.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <algorithm>
#include <regex>
#include <sstream>

#include "r2plugin/r2info.h"
#include "r2plugin/r2utils.h"

using namespace retdec::r2plugin;

/**
 * Empty body for the destructor. The will forbid FormatUtils class
 * to be instanciated.
 */
FormatUtils::~FormatUtils()
{
}

/**
 * Translation map betwen C types and LLVM IR types. In future we might
 * consider using some kind of LLVM library method for this but it would
 * only include LLVM dependency (on the other hand size of this map might
 * get out of control).
 */
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

/**
 * Special keywords that are right now neglected during translation.
 */
const std::vector<std::string> FormatUtils::_typeKeywords = {
	"const",
	"struct",
	"unsigned",
	"signed"
};

/**
 * @brief Joins vector of tokens into one string separated by delim.
 */
const std::string FormatUtils::joinTokens(const std::vector<std::string> &tokens, const std::string &delim)
{
	if (tokens.empty()) {
		return "";
	}

	std::ostringstream finalstr;
	std::copy(tokens.begin(), tokens.end()-1,
		   std::ostream_iterator<std::string>(finalstr, delim.c_str()));

	return finalstr.str()+tokens.back();
}

/**
 * @brief Splits continuous string of tokens separated by delim into vector of such tokens.
 */
std::vector<std::string> FormatUtils::splitTokens(const std::string &type, char delim)
{
	std::vector<std::string> tokensResult;
	std::istringstream iss(type);
	std::string token;

	while (getline(iss, token, delim)) {
		tokensResult.push_back(token);
	}

	return tokensResult;
}

/**
 * @brief Strips additional info from function names that is added by Radare2.
 */
std::string FormatUtils::stripName(const std::string &name)
{
	static const std::vector r2Prefix = {"sym.", "fcn.", "imp.", "__isoc99_"};

	std::string_view v = name;
	for (auto px: r2Prefix) {
		if (v.length() <= std::strlen(px))
			continue;

		if (v.compare(0, std::strlen(px), px) == 0)
			v.remove_prefix(std::strlen(px));
	}

	std::string newName(v);

	if (newName.empty() || std::all_of(newName.begin(), newName.end(), ::isxdigit)) {
		return "fcn_"+newName;
	}

	return newName;
}

/**
 * @brief Provides convertion of C type into LLVM type.
 *
 * TODO: provide more complex types parsing.
 */
const std::string FormatUtils::convertTypeToLlvm(const std::string &ctype)
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
			if (cm.size() != 3) {
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
			if (cm.size() != 2) {
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

/**
 * @brief Returns definition of a complex type provided by user.
 *
 * TODO: this method now returns only void.
 */
const std::string FormatUtils::getTypeDefinition(const std::string &token)
{
	return "void";
}
