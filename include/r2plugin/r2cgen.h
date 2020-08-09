/**
 * @file include/r2plugin/r2cgen.h
 * @brief C code generation and token marking.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#ifndef RETDEC_R2PLUGIN_R2CGEN_H
#define RETDEC_R2PLUGIN_R2CGEN_H

#include <map>
#include <optional>
#include <rapidjson/document.h>

#include <retdec/common/address.h>
#include <r_util/r_annotated_code.h>

namespace retdec {
namespace r2plugin {

class R2CGenerator {
public:
	RAnnotatedCode* generateOutput(const std::string &rdoutJson) const;

protected:
	RAnnotatedCode* provideAnnotations(const rapidjson::Document &root) const;
	void annotate(
		RAnnotatedCode* code,
		const common::Address& binAdress,
		const common::AddressRange& inCode) const;

	void annotate(
		RAnnotatedCode* code,
		const RSyntaxHighlightType& high,
		const common::AddressRange& inCode) const;

	std::optional<RCodeAnnotation> specialAnnotation(
		const std::string& kind,
		const std::string& val,
		const std::optional<common::Address>& address) const;

	std::optional<RSyntaxHighlightType> highlightTypeForToken(const std::string &token) const;

private:
	static std::map<const std::string, RSyntaxHighlightType> _hig2token;
};

}
}

#endif /*RETDEC_R2PLUGIN_R2CGEN_H*/
