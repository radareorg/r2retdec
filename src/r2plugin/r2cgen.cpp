/**
 * @file src/r2plugin/r2cgen.cpp
 * @brief C code generation and token marking.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <fstream>
#include <optional>

#include "r2plugin/r2data.h"
#include "r2plugin/r2cgen.h"

using namespace retdec::r2plugin;

/**
 * Translation map between decompilation JSON output and r2 understandable
 * annotations.
 */
std::map<const std::string, RSyntaxHighlightType> R2CGenerator::_hig2token = {
	// {"nl", ... }
	// {"ws", ... }
	// {"punc", ... }
	// {"op", ... }
	{"i_var", R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE},
	{"i_lvar", R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE},
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

/**
 * Translaction map interaction method. Usage of this method is preffered to obtain r2 understandable
 * annotation from JSON config token.
 */
std::optional<RSyntaxHighlightType> R2CGenerator::highlightTypeForToken(const std::string &token) const
{
	if (_hig2token.count(token)) {
		return _hig2token.at(token);
	}

	return {};
}

/**
 * Generates annotated code from RetDec's output obrained as JSON.
 *
 * @param root The root of JSON decompilation output.
 */
RAnnotatedCode* R2CGenerator::provideAnnotations(const rapidjson::Document &root) const
{
	RAnnotatedCode *code = r_annotated_code_new(nullptr);
	if (code == nullptr) {
		throw DecompilationError("unable to allocate memory");
	}

	std::ostringstream planecode;
	std::optional<common::Address> lastAddr;

	if (!root["tokens"].IsArray()) {
		throw DecompilationError("malformed JSON");
	}

	auto tokens = root["tokens"].GetArray();
	for (auto& token: tokens) {
		if (token.HasMember("addr")) {
			std::string addrRaw = token["addr"].GetString();
			if (addrRaw == "") {
				lastAddr.reset();
			}
			else {
				try {
					lastAddr = std::stoll(addrRaw, nullptr, 16);
				} catch (std::exception &e) {
					throw DecompilationError("invalid address: "+addrRaw);
				}
			}
			continue;
		}
		else if (token.HasMember("val") && token.HasMember("kind")) {
			// Beginning position in the code.
			unsigned long bpos = planecode.tellp();
			planecode << token["val"].GetString();
			// Ending position in the code
			unsigned long epos = planecode.tellp();

			if (lastAddr.has_value())
				annotate(code, lastAddr.value(), {bpos, epos});

			auto highlight = highlightTypeForToken(token["kind"].GetString());
			if (highlight.has_value())
				annotate(code, highlight.value(), {bpos, epos});

			auto special = specialAnnotation(
				token["kind"].GetString(),
				token["val"].GetString(),
				lastAddr);

			if (special.has_value()) {
				auto specialAnnotation = special.value();
				specialAnnotation.start = bpos;
				specialAnnotation.end = epos;
				r_annotated_code_add_annotation(code, &specialAnnotation);
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

/**
 * Generates annotation of the address.
 */
void R2CGenerator::annotate(
	RAnnotatedCode* code,
	const common::Address& binAdress,
	const common::AddressRange& inCode) const
{
	RCodeAnnotation annotation = {};
	annotation.type = R_CODE_ANNOTATION_TYPE_OFFSET;
	annotation.offset.offset = binAdress.getValue();
	annotation.start = inCode.getStart().getValue();
	annotation.end = inCode.getEnd().getValue();
	r_annotated_code_add_annotation(code, &annotation);
}

/**
 * Generates syntax highlight annotation.
 */
void R2CGenerator::annotate(
	RAnnotatedCode* code,
	const RSyntaxHighlightType& highlight,
	const common::AddressRange& inCode) const
{
	RCodeAnnotation annotation = {};
	annotation.type = R_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT;
	annotation.syntax_highlight.type = highlight;
	annotation.start = inCode.getStart().getValue();
	annotation.end = inCode.getEnd().getValue();
	r_annotated_code_add_annotation(code, &annotation);
}

/**
 * Possibly creates special annotation based on kind, value and address.
 */
std::optional<RCodeAnnotation> R2CGenerator::specialAnnotation(
		const std::string& kind,
		const std::string& val,
		const std::optional<common::Address>& address) const
{
	auto hl = highlightTypeForToken(kind);
	if (!hl.has_value())
		return {};

	auto offset = [kind](const std::optional<common::Address>& a) -> common::Address {
		if (!a.has_value())
			throw DecompilationError("expected offset for "+kind);

		return a->getValue();
	};

	RCodeAnnotation an;

	switch (hl.value()) {
	case R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME:
		an.type = R_CODE_ANNOTATION_TYPE_FUNCTION_NAME;
		an.reference.name = strdup(val.c_str());
		an.reference.offset = offset(address);
		return an;

	case R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE:
		an.type = R_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE;
		an.reference.offset = offset(address);
		return an;

	case R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE:
		an.type = R_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE;
		an.reference.offset = offset(address);
		return an;

	case R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE:
		an.type = R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE;
		an.variable.name = strdup(val.c_str());
		return an;

	case R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER:
		an.type = R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER;
		an.variable.name = strdup(val.c_str());
		return an;

	default:
		return {};
	}
}

/**
 * Generates output by parsing RetDec's JSON output and calling R2CGenerator::provideAnnotations.
 */
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

	rapidjson::Document root;
	rapidjson::ParseResult success = root.Parse(jsonContent);
	if (!success) {
		throw DecompilationError("unable to parse RetDec JSON output");
	}

	return provideAnnotations(root);
}
