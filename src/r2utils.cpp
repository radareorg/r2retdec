#include "r2utils.h"

using namespace retdec::r2plugin;

std::map<const std::string, const std::string> CTypeConverter::_primitives {
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

std::vector<std::string> CTypeConverter::_type_keywords = {
	"const",
	"struct",
	"unsigned",
	"signed"
};

const std::string CTypeConverter::convert(const std::string &ctype) const
{
	if (_primitives.count(ctype))
		return _primitives[ctype];

	return "void";
}
