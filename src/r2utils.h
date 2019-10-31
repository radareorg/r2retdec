#ifndef RETDEC_R2PLUGIN_R2UTILS_H
#define RETDEC_R2PLUGIN_R2UTILS_H

#include <map>
#include <string>
#include <vector>

#include <r_core.h>

namespace retdec {
namespace r2plugin {

class CTypeConverter {
public:
	const std::string convert(const std::string &ctype) const;

private:
	static std::map<const std::string, const std::string> _primitives;
	static std::vector<const std::string> _type_keywords;
};

}
}

#endif /*RETDEC_R2PLUGIN_R2UTILS_H*/
