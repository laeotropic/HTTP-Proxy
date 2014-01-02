#ifndef __HTTPPROXY__STRINGUTIL__HPP__
#define __HTTPPROXY__STRINGUTIL__HPP__

#include <string>
#include <algorithm>
#include <functional>

namespace StringUtil {
	static inline std::string ltrim(std::string s) {
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
		return s;
	}

	static inline std::string rtrim(std::string s) {
		s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
		return s;
	}

	static inline std::string trim(std::string s) {
		return ltrim(rtrim(s));
	}

	static inline std::string upper(std::string s) {
		std::transform(s.begin(), s.end(), s.begin(), ::toupper);
		return s;
	}

	static inline bool equal_case_insensitive(const std::string& a, const std::string& b) {
		if (a.length() != b.length()) return false;
		return std::equal(a.begin(), a.end(), b.begin(), [](char a, char b){ return ::toupper(a) == ::toupper(b); });
	}

	struct case_insensitive_compare {
		bool operator()(const std::string& a, const std::string& b) const {
			return upper(a) < upper(b);
		}
	};
};

#endif