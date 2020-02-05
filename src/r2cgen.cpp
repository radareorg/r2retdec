/**
 * @file src/r2cgen.cpp
 * @brief C code generation and token marking.
 * @copyright (c) 2019 Avast Software, licensed under the LGPLv3 license.
 */

#include <fstream>
#include <optional>

#include "r2plugin/r2info.h"
#include "r2plugin/r2cgen.h"

using namespace retdec::r2plugin;

std::map<const std::string, RSyntaxHighlightType> R2CGenerator::_hig2token = {
	// {"nl", ... }
	// {"ws", ... }
	// {"punc", ... }
	// {"op", ... }
	{"i_var", R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE},
	// {"i_var", R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE},
	// {"i_mem", R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE},
	{"i_lab", R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD},
	{"i_fnc", R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME},
	{"i_arg", R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER},
	{"keyw" , R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD},
	{"type" , R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE},
	{"preproc" , R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD},
	{"inc", R_SYNTAX_HIGHLIGHT_TYPE_COMMENT},
	{"l_bool", R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_int", R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_fp", R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_str", R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_sym", R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_ptr", R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"cmnt" , R_SYNTAX_HIGHLIGHT_TYPE_COMMENT}
};

std::optional<RSyntaxHighlightType> R2CGenerator::highlightTypeForToken(const std::string &token) const
{
	if (_hig2token.count(token)) {
		return _hig2token.at(token);
	}
	
	return {};
}

RAnnotatedCode* R2CGenerator::provideAnnotations(const Json::Value &root) const
{
	RAnnotatedCode *code = r_annotated_code_new(nullptr);
	if (code == nullptr) {
		throw DecompilationError("unable to allocate memory");
	}

	std::ostringstream planecode;
	std::optional<unsigned long> lastAddr;

	auto tokens = root["tokens"];
	for (auto token: tokens) {
		if (token.isMember("addr")) {
			std::string addrRaw = token["addr"].asString();
			if (addrRaw == "") {
				lastAddr.reset();
			}
			else {
				try {
					lastAddr = std::stol(addrRaw, nullptr, 16);
				} catch (std::exception &e) {
					throw DecompilationError("invalid address: "+addrRaw);
				}
			}
			continue;
		}
		else if (token.isMember("val") && token.isMember("kind")) {
			unsigned long bpos = planecode.tellp();
			planecode << token["val"].asString();
			unsigned long epos = planecode.tellp();

			if (lastAddr.has_value()) {
				RCodeAnnotation annotation = {};
				annotation.type = R_CODE_ANNOTATION_TYPE_OFFSET;
				annotation.offset.offset = lastAddr.value();
				annotation.start = bpos;
				annotation.end = epos;
				r_annotated_code_add_annotation(code, &annotation);
			}

			auto higlight = highlightTypeForToken(token["kind"].asString());
			if (higlight.has_value()) {
				RCodeAnnotation annotation = {};
				annotation.type = R_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT;
				annotation.syntax_highlight.type = higlight.value();
				annotation.start = bpos;
				annotation.end = epos;
				r_annotated_code_add_annotation(code, &annotation);
			}
		}
		else {
			throw DecompilationError("malformed RetDec JSON output");
		}
	}

	std::string str = planecode.str();
	code->code = reinterpret_cast<char *>(r_malloc(str.length() + 1));
	if(!code->code) {
		r_annotated_code_free(code);
		throw DecompilationError("unable to allocate memory");
	}
	memcpy(code->code, str.c_str(), str.length());
	code->code[str.length()] = '\0';

	return code;
}

RAnnotatedCode* R2CGenerator::generateOutput(const std::string &rdoutJson) const
{
	std::ifstream jsonFile(rdoutJson, std::ios::in | std::ios::binary);
	if (!jsonFile) {
		throw DecompilationError("unable to open RetDec output: "+rdoutJson);
	}

	std::string jsonContent;
	jsonFile.seekg(0, std::ios::end);
	jsonContent.resize(jsonFile.tellg());
	jsonFile.seekg(0, std::ios::beg);
	jsonFile.read(&jsonContent[0], jsonContent.size());
	jsonFile.close();

	Json::Value root;
	std::string errs;
	std::istringstream json(jsonContent);
	Json::CharReaderBuilder rbuilder;

	bool success = Json::parseFromStream(rbuilder, json, &root, &errs);

	if (!success || root.isNull() || !root.isObject() ) {
		throw DecompilationError("unable to parse RetDec JSON output");
	}

	return provideAnnotations(root);
}
