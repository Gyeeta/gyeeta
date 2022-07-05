
#pragma			once

#include		"gy_common_inc.h"
#include		"gy_print_offload.h"

/*
 * XXX : Not being used as worst case run time performance is wayyyy worse than re2 with best case as well
 * being wayyy better than re2. Need to work on parsing the regex and branching based on whether the regex is simple enough
 *
 * Features : No heap allocations either during compile or test. Per Object size ~ 2KB for default template params.
 * Supports a subset of regex. 
 *
 * Modified version of https://github.com/kokke/tiny-regex-c.git
 *
 * Supports:
 * ---------
 *   '.'        Dot, matches any character
 *   '^'        Start anchor, matches beginning of string
 *   '$'        End anchor, matches end of string
 *   '*'        Asterisk, match zero or more (greedy)
 *   '+'        Plus, match one or more (greedy)
 *   '?'        Question, match zero or one (non-greedy)
 *   '[abc]'    Character class, match if one of {'a', 'b', 'c'}
 *   '[^abc]'   Inverted class, match if NOT one of {'a', 'b', 'c'} -- NOTE: feature is currently broken!
 *   '[a-zA-Z]' Character ranges, the character set of the ranges { a-z | A-Z }
 *   {2,5}      Repetitions
 *   '\s'       Whitespace, \t \f \r \n \v and spaces
 *   '\S'       Non-whitespace
 *   '\w'       Alphanumeric, [a-zA-Z0-9_]
 *   '\W'       Non-alphanumeric
 *   '\d'       Digits, [0-9]
 *   '\D'       Non-digits
 *
 * Missing:
 * -------
 *    |         Branching (abc|def)
 *  (re)        Grouping capture
 * \A \b \B \z  Escape characters
 *  [[:*:]]     Character classes -- TODO Replace pattern instead of erroring out 
 *
 * For case insensitive search, prefix the pattern (?i) before the required pattern as in : '(?i)host[0-9]*[dp][er].*\.local'
 * Will support case sensitiveness only for ASCII characters. UTF8 chars over ASCII range will be compared as is.
 */

namespace gyeeta {


template <size_t MaxPatternLen = 128>
class TinyRegexInt
{
public :
	static constexpr size_t		MAX_CHAR_CLASS_LEN = std::min<size_t>(MaxPatternLen - 2, 80);
	static constexpr int		MAX_LOOP_CHECKS = 10;

	enum RTYPE_E : unsigned char {
		UNUSED, DOT, BEGIN, END, QUESTIONMARK, STAR, PLUS, CHAR, CHAR_CLASS, INV_CHAR_CLASS, DIGIT, NOT_DIGIT, ALPHA, NOT_ALPHA, WHITESPACE, NOT_WHITESPACE, /* BRANCH */ 
	};	

	struct regex_t
	{
		RTYPE_E			type;  	
		union
		{
			unsigned char	ch;   	/*      the character itself             */
			unsigned char	*ccl;  	/*  OR  a pointer to characters in class */
		};
	};

	regex_t 			re_compiled_[MaxPatternLen];
	regex_t				guardbuf_				{END, 0ul};
	union {
		unsigned char 		ccl_buf_[MAX_CHAR_CLASS_LEN];	
		char			error_buf_[84];				// Will be used as error string in case of compile failure
	};	
	bool				is_case_insensitive_			{false};
	bool				is_compiled_				{false};

	static constexpr const char	invalid_chars_[] = "(|";

	static_assert(MaxPatternLen < 1024, 	"Maximum Pattern Length is limited to 1 KB");
	static_assert(MaxPatternLen >= 24, 	"Minimum Pattern Length is 24 bytes");

	/*
	 * Will support case sensitiveness only for ASCII characters. UTF8 chars over ASCII range will be compared as is
	 */
	TinyRegexInt(const char *pattern, bool throw_on_error = true, bool is_case_insensitive = false)
		: is_case_insensitive_(is_case_insensitive)
	{
		*ccl_buf_ 	= 0;

		constexpr size_t	szigncase = GY_CONST_STRLEN("(?i)");
		size_t			sz = strnlen(pattern, MaxPatternLen + szigncase);
		const char		*ptmp;
		
		if (sz > szigncase && (0 == std::memcmp(pattern, "(?i)", szigncase))) {

			is_case_insensitive_ 	= true;
			pattern 		+= szigncase;
			sz 			-= szigncase;
		}

		if (sz >= MaxPatternLen) {
			if (throw_on_error) {
				GY_THROW_EXCEPTION("Max Length of Regex Pattern exceeded : Max allowed is %lu", MaxPatternLen);
			}
			snprintf(error_buf_, sizeof(error_buf_), "Max Length of Regex Pattern exceeded : Max allowed is %lu", MaxPatternLen);
			return;
		}

		if ((ptmp = strpbrk(pattern, invalid_chars_))) {
			if (throw_on_error) {
				if (*ptmp == '{') {
					GY_THROW_EXCEPTION("Regex Pattern containing Repetitions using {} not currently supported. Please use .* or exact matches");
				}	
				GY_THROW_EXCEPTION("Regex pattern containing \'%s\' not currently supported", invalid_chars_);
			}
			

			if (*ptmp == '{') {
				snprintf(error_buf_, sizeof(error_buf_), "Regex Pattern containing Repetitions using {} not currently supported. Please use .* or exact matches");
			}	
			else {
				snprintf(error_buf_, sizeof(error_buf_), "Regex pattern containing \'%s\' not currently supported", invalid_chars_);
			}	
			return;
		}	
	
		if (strstr(pattern, ":]]")) {
			if (throw_on_error) {
				GY_THROW_EXCEPTION("Regex pattern containing [[:*:]] not currently supported");
			}
			snprintf(error_buf_, sizeof(error_buf_), "Regex pattern containing [[:*:]] not currently supported");
			return;
		}

		char		tbuf[MaxPatternLen];
		
		if (is_case_insensitive == false) {
			std::memcpy(tbuf, pattern, sz);
		}
		else {
			for (int i = 0; (size_t)i < sz; ++i) {
				tbuf[i] = gy_tolower_ascii(pattern[i]);
			}	
		}

		tbuf[sz] = 0;

		reg_compile(tbuf, sz, throw_on_error);
	}

	bool is_valid() const noexcept
	{
		return is_compiled_;
	}

	const char * get_error() const noexcept
	{
		if (is_compiled_ == false) {
			return error_buf_;
		}	

		return "";
	}	

	static bool regex_match(const char *text, const char *pattern, bool throw_on_error = true, bool is_case_insensitive = false, const char ** pmatchstart = nullptr, int * pmatchlength = nullptr)
	{
		TinyRegexInt		reg(pattern, throw_on_error, is_case_insensitive);
		
		return regex_match_compiled(text, reg, pmatchstart, pmatchlength);
	}	

	static bool regex_match_compiled(const char *text, const TinyRegexInt & reg, const char ** pmatchstart = nullptr, int * pmatchlength = nullptr) noexcept
	{
		if (false == reg.is_valid()) {
			return false;
		}

		int			ret;

		ret = reg.reg_match_compiled(text, pmatchlength);

		if (pmatchstart) {
			if (ret >= 0) {
				*pmatchstart = text + ret;
			}
			else {
				*pmatchstart = nullptr;
			}	
		}	

		return (ret >= 0);
	}	

protected :

	int reg_match_compiled(const char * text, int * pmatchlength = nullptr) const noexcept
	{
		if (is_compiled_ == false) {
			return -1;
		}	

		int		matchlength, *pmatchlen = pmatchlength ? pmatchlength : &matchlength, nloops = 0;
		auto		pattern = re_compiled_;
		
		*pmatchlen = 0;

		if (pattern[0].type == BEGIN)
		{
			return ((matchpattern(&pattern[1], text, pmatchlen, nloops)) ? 0 : -1);
		}
		else
		{
			int idx = -1;

			do
			{
				idx += 1;
				nloops = 0;	

				if (matchpattern(pattern, text, pmatchlen, nloops))
				{
					if (text[0] == '\0')
						return -1;

					return idx;
				}
			}
			while (*text++ != '\0');
		}
		return -1;
	}

	void reg_compile(const char *pattern, size_t szpattern, bool throw_on_error = false)
	{
		int 			ccl_bufidx = 1;
		unsigned char 		c;     /* current char in pattern   */
		int 			i = 0;  /* index into pattern        */
		int 			j = 0;  /* index into re_compiled_    */

		#define check_prev_not_same(_c)															\
		do {																		\
			if (j > 0) {																\
				if (re_compiled_[j].type == re_compiled_[j - 1].type) {										\
					if (throw_on_error) {													\
						GY_THROW_EXCEPTION("Regex Pattern Error : Invalid Regex pattern : Multiple %c chars seen", _c);			\
					} 															\
					snprintf(error_buf_, sizeof(error_buf_), "Regex Pattern Error : Invalid Regex pattern : Multiple %c chars seen", _c);	\
					return;															\
				}																\
			}																	\
		} while (false)

		while ((size_t)i < szpattern && pattern[i] != '\0' && ((size_t)j + 1 < MaxPatternLen))
		{
			c = (unsigned char)pattern[i];

			switch (c)
			{
				/* Meta-characters: */
				case '^': { re_compiled_[j].type = BEGIN; 	check_prev_not_same(c); } break;
				case '$': { re_compiled_[j].type = END; 	check_prev_not_same(c); } break;
				case '.': { re_compiled_[j].type = DOT;         check_prev_not_same(c); } break;
				case '*': { re_compiled_[j].type = STAR;        check_prev_not_same(c); } break;
				case '+': { re_compiled_[j].type = PLUS;        check_prev_not_same(c); } break;
				case '?': { re_compiled_[j].type = QUESTIONMARK;check_prev_not_same(c); } break;

			  /*    case '|': {    re_compiled_[j].type = BRANCH;          } break; <-- not working properly */

				/* Escaped character-classes (\s \w ...): */
				case '\\':
					  {
						  if (pattern[i+1] != '\0')
						  {
							  /* Skip the escape-char '\\' */
							  i += 1;
							  /* ... and check the next */
							  switch (pattern[i])
							  {
								  /* Meta-character: */
								  case 'd': {    re_compiled_[j].type = DIGIT;            } break;
								  case 'D': {    re_compiled_[j].type = NOT_DIGIT;        } break;
								  case 'w': {    re_compiled_[j].type = ALPHA;            } break;
								  case 'W': {    re_compiled_[j].type = NOT_ALPHA;        } break;
								  case 's': {    re_compiled_[j].type = WHITESPACE;       } break;
								  case 'S': {    re_compiled_[j].type = NOT_WHITESPACE;   } break;

								  case 'A':
								  case 'b':
								  case 'B':
								  case 'z':
									  if (throw_on_error) {
										GY_THROW_EXCEPTION("Regex Pattern Error : Escape characters \\A, \\b, \\B, \\z not supported");
								 	  } 
									  snprintf(error_buf_, sizeof(error_buf_), "Regex Pattern Error : Escape characters \\A, \\b, \\B, \\z not supported");
									  return;
								  	
								  /* Escaped character, e.g. '.' or '$' */ 
								  default:  
									re_compiled_[j].type = CHAR;
									re_compiled_[j].ch = pattern[i];
									break;
							  }
						  }
						  /* '\\' as last char in pattern -> invalid regular expression. */
						  /*
						     else
						     { 
						     re_compiled_[j].type = CHAR;
						     re_compiled_[j].ch = pattern[i];
						     }
						   */
					  } break;

				/* Character class: */
				case '[':
					  {
						  /* Remember where the char-buffer starts. */
						  int buf_begin = ccl_bufidx;

						  /* Look-ahead to determine if negated */
						  if (pattern[i+1] == '^')
						  {
							  re_compiled_[j].type = INV_CHAR_CLASS;
							  i += 1; /* Increment i to avoid including '^' in the char-buffer */
						  }  
						  else
						  {
							  re_compiled_[j].type = CHAR_CLASS;
						  }

						  /* Copy characters inside [..] to buffer */
						  while ((pattern[++i] != ']') && (pattern[i]   != '\0')) /* Missing ] */
						  {
							  if (pattern[i] == '\\')
							  {
								  if ((size_t)ccl_bufidx >= MAX_CHAR_CLASS_LEN - 1)
								  {
									  if (throw_on_error) {
										GY_THROW_EXCEPTION("Regex Pattern Error : Max Char Class [*] check length exceeded");
								 	  } 
									  snprintf(error_buf_, sizeof(error_buf_), "Regex Pattern Error : Max Char Class [*] check length exceeded");
									  return;
								  }
								  ccl_buf_[ccl_bufidx++] = pattern[i++];
							  }
							  else if ((size_t)ccl_bufidx >= MAX_CHAR_CLASS_LEN)
							  {
								  if (throw_on_error) {
									GY_THROW_EXCEPTION("Regex Pattern Error : Max Char Class [*] check length exceeded");
							 	  } 

								  snprintf(error_buf_, sizeof(error_buf_), "Regex Pattern Error : Max Char Class [*] check length exceeded");
								  return;
							  }
							  ccl_buf_[ccl_bufidx++] = pattern[i];
						  }
						  if ((size_t)ccl_bufidx >= MAX_CHAR_CLASS_LEN)
						  {
							  /* Catches cases such as [000000000000000000][ */
							  if (throw_on_error) {
								GY_THROW_EXCEPTION("Regex Pattern Error : Max Char Class [*] check length exceeded");
						 	  } 
							  snprintf(error_buf_, sizeof(error_buf_), "Regex Pattern Error : Max Char Class [*] check length exceeded");

							  return;
						  }
						  /* Null-terminate string end */
						  ccl_buf_[ccl_bufidx++] = 0;
						  re_compiled_[j].ccl = &ccl_buf_[buf_begin];
					  } break;

				// Repetition
				case '{':
					{
						int		ri = i + 1, origj= j - 1, n1 = 0, n2 = 0;
						char		c1 = pattern[ri], c2 = 0, c3 = 0, ct = 0;

						if (j > 0 && (pattern[ri] >= '0' && pattern[ri] <= '9')) {

							n1 = c1 - '0';

							c2 = pattern[ri + 1];

							if (c2 != 0) {
								if (c2 >= '0' && c2 <= '9') {
									n1 = n1 * 10 + c2 - '0';

									c2 = pattern[ri + 2];

									if (c2 != 0) {
										if (c2 >= '0' && c2 <= '9') {
											  if (throw_on_error) {
												GY_THROW_EXCEPTION("Regex Pattern Error : Max Repetition is limited to 99 currently");
											  } 
											  snprintf(error_buf_, sizeof(error_buf_), 
												"Regex Pattern Error : Max Repetition is limited to 99 currently");
											  return;
										}

										c3 = pattern[ri + 3];

										if (c2 == ',') {
lab2 :
											if (c3 >= '0' && c3 <= '9') {

												n2 = c3 - '0';
												
												ct = pattern[ri + 4];

												if (ct >= '0' && ct <= '9') {
													n2 = n2 * 10 + ct - '0';

													ct = pattern[ri + 5];

													if (ct != '}') {
														if (throw_on_error) {
															GY_THROW_EXCEPTION("Regex Pattern Error : Max Repetition is limited to 99 currently");
														} 
														snprintf(error_buf_, sizeof(error_buf_), 
															"Regex Pattern Error : Max Repetition is limited to 99 currently");
														return;
													}	
												}	

												if (n2 < n1) {
													goto doneerr;
												}	
												else if (n2 - n1 > MAX_LOOP_CHECKS) {
													if (throw_on_error) {
														GY_THROW_EXCEPTION(
															"Regex Pattern Error : Max Repetition difference is limited to %d currently", 
															MAX_LOOP_CHECKS);
													}
													snprintf(error_buf_, sizeof(error_buf_), 
														"Regex Pattern Error : Max Repetition difference is limited to %d currently",
														MAX_LOOP_CHECKS);
													return;
												}	

											}	
											else if (c3 != '}') {
												goto doneerr;
											}	
										}	
										else if (c2 != '}') {
											goto doneerr;
										}	
									}
									else {
										goto doneerr;	
									}	
								}	
								else {
									if (c2 == ',') {
										c3 = pattern[ri + 2];

										ri--;
										goto lab2;
									}
									else if (c2 != '}') {
										goto doneerr;
									}	
								}
							}	
							else {
								goto doneerr;
							}	


							if (j + n1 + 3 >= (int)MaxPatternLen + 1) {
								  if (throw_on_error) {
									GY_THROW_EXCEPTION("Regex Pattern Error : Max Repetition Count length %lu exceeded : Currently not supported", 
										MaxPatternLen);
								  } 
								  snprintf(error_buf_, sizeof(error_buf_), 
									"Regex Pattern Error : Max Repetition Count length %lu exceeded : Currently not supported", MaxPatternLen);
								  return;
							}	

							for (int t = 0; t < 8; ++t) {
								char		ce = pattern[i + t];

								if (ce == '}') {
									i += t;
									break;
								}	
							}

							if (pattern[i] != '}') {
								goto doneerr;
							}

							i++;

							for (int t = 0; t < n1 - 1; ++t) {
								re_compiled_[j + t].type = re_compiled_[origj].type;
								re_compiled_[j + t].ccl = re_compiled_[origj].ccl;
							}	

							if (n1 > 0) {
								j += n1 - 1;
							}
							else {
								n1 = 1;
							}	

							if (c2 == ',') {
								if (c3 == '}') {
									re_compiled_[j].type = re_compiled_[origj].type;
									re_compiled_[j].ccl = re_compiled_[origj].ccl;
									j++;

									re_compiled_[j++].type = STAR;
									goto done1;
								}	

								if (j + (n2 - n1) * 2 + 2 >= (int)MaxPatternLen + 1) {
									  if (throw_on_error) {
										GY_THROW_EXCEPTION("Regex Pattern Error : Max Repetition Count length %lu exceeded : Currently not supported", 
											MaxPatternLen);
									  } 
									  snprintf(error_buf_, sizeof(error_buf_), 
										"Regex Pattern Error : Max Repetition Count length %lu exceeded : Currently not supported", MaxPatternLen);
									  return;
								}	

								for (int t = 0; t < n2 - n1; ++t) {
									re_compiled_[j + t * 2].type = re_compiled_[origj].type;
									re_compiled_[j + t * 2].ccl = re_compiled_[origj].ccl;

									re_compiled_[j + t * 2 + 1].type = QUESTIONMARK;
								}	

								j += (n2 - n1) * 2;

								goto done1;
							}	
							else {
								goto done1;
							}	
						}	
						else {
doneerr :							
							  if (throw_on_error) {
								GY_THROW_EXCEPTION("Regex Pattern Error : Character pattern containing { not valid or is an unsupported format");
							  } 
							  snprintf(error_buf_, sizeof(error_buf_), "Regex Pattern Error : Character pattern containing { not valid or is an unsupported format");
							  return;

						}	

					} break;	

				/* Other characters: */
				default:
					re_compiled_[j].type = CHAR;
					re_compiled_[j].ch = c;
					break;
			} // switch

			i++;
			j++;

done1 :
			;
		}

		if ((size_t)i < szpattern && pattern[i] != '\0') {
			  if (throw_on_error) {
				GY_THROW_EXCEPTION("Regex Pattern Error : Repetition Count resulted in exceeded pattern length : Currently not supported");
			  } 
			  snprintf(error_buf_, sizeof(error_buf_), "Regex Pattern Error : Repetition Count resulted in exceeded pattern length : Currently not supported");
			  return;
		}

		/* 'UNUSED' is a sentinel used to indicate end-of-pattern */
		if ((unsigned)j < MaxPatternLen) {
			re_compiled_[j].type = UNUSED;
		}
		else {
			re_compiled_[MaxPatternLen - 1].type = UNUSED;
		}

		is_compiled_ = true;

		#undef check_prev_not_same

	}

	int matchdigit(char c) const noexcept
	{
		return ((c >= '0') && (c <= '9'));
	}

	int matchalpha(char c) const noexcept
	{
		return ((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z'));
	}

	int matchwhitespace(char c) const noexcept
	{
		return ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r') || (c == '\f') || (c == '\v'));
	}

	int matchalphanum(char c) const noexcept
	{
		return ((c == '_') || matchalpha(c) || matchdigit(c));
	}

	int matchrange(char c, const char* str) const noexcept
	{
		return ((c != '-') && (str[0] != '\0') && (str[0] != '-') &&
				(str[1] == '-') && (str[1] != '\0') &&
				(str[2] != '\0') && ((c >= str[0]) && (c <= str[2])));
	}

	int ismetachar(char c) const noexcept
	{
		return ((c == 's') || (c == 'S') || (c == 'w') || (c == 'W') || (c == 'd') || (c == 'D'));
	}

	int matchmetachar(char c, const char* str) const noexcept
	{
		switch (str[0])
		{
			case 'd': return  matchdigit(c);
			case 'D': return !matchdigit(c);
			case 'w': return  matchalphanum(c);
			case 'W': return !matchalphanum(c);
			case 's': return  matchwhitespace(c);
			case 'S': return !matchwhitespace(c);
			default:  return (c == str[0]);
		}
	}

	int matchcharclass(char c, const char* str) const noexcept
	{
		do
		{
			if (matchrange(c, str))
			{
				return 1;
			}
			else if (str[0] == '\\')
			{
				/* Escape-char: increment str-ptr and match on next char */
				str += 1;
				if (matchmetachar(c, str))
				{
					return 1;
				} 
				else if ((c == str[0]) && !ismetachar(c))
				{
					return 1;
				}
			}
			else if (c == str[0])
			{
				if (c == '-')
				{
					return ((str[-1] == '\0') || (str[1] == '\0'));
				}
				else
				{
					return 1;
				}
			}
		}
		while (*str++ != '\0');

		return 0;
	}

	int matchone(regex_t p, char c) const noexcept
	{
		switch (p.type)
		{
			case DOT:            return 1;
			case CHAR_CLASS:     return  matchcharclass(c, (const char*)p.ccl);
			case INV_CHAR_CLASS: return !matchcharclass(c, (const char*)p.ccl);
			case DIGIT:          return  matchdigit(c);
			case NOT_DIGIT:      return !matchdigit(c);
			case ALPHA:          return  matchalphanum(c);
			case NOT_ALPHA:      return !matchalphanum(c);
			case WHITESPACE:     return  matchwhitespace(c);
			case NOT_WHITESPACE: return !matchwhitespace(c);
			
			default:             return  (p.ch == (is_case_insensitive_ ? gy_tolower_ascii(c) : c));
		}
	}

	int matchstar(regex_t p, const regex_t * pattern, const char* text, int* matchlength, int & nloops) const noexcept
	{
		int prelen = *matchlength;
		const char* prepoint = text;
		while ((text[0] != '\0') && matchone(p, *text))
		{
			text++;
			(*matchlength)++;
		}
		while (text >= prepoint)
		{
			if (matchpattern(pattern, text--, matchlength, nloops))
				return 1;
			(*matchlength)--;
		}

		*matchlength = prelen;
		return 0;
	}

	int matchplus(regex_t p, const regex_t * pattern, const char* text, int* matchlength, int & nloops) const noexcept
	{
		const char* prepoint = text;
		while ((text[0] != '\0') && matchone(p, *text))
		{
			text++;
			(*matchlength)++;
		}
		while (text > prepoint)
		{
			if (matchpattern(pattern, text--, matchlength, nloops))
				return 1;
			(*matchlength)--;
		}

		return 0;
	}

	int matchquestion(regex_t p, const regex_t * pattern, const char* text, int* matchlength, int & nloops) const noexcept
	{
		if (p.type == UNUSED)
			return 1;
		if (matchpattern(pattern, text, matchlength, nloops))
			return 1;
		if (*text && matchone(p, *text++))
		{
			if (matchpattern(pattern, text, matchlength, nloops))
			{
				(*matchlength)++;
				return 1;
			}
		}
		return 0;
	}


	/* Iterative matching */
	int matchpattern(const regex_t* pattern, const char* text, int* matchlength, int & nloops) const noexcept
	{
		const regex_t	* const endpattern = re_compiled_ + MaxPatternLen;
		int 			pre = *matchlength;

		nloops++;
		
		if (nloops > MAX_LOOP_CHECKS) {
			CONDEXEC(
				DEBUGEXECN(20,
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Too many loops seen while tiny regex match. Bailing out...\n");
				);
			);
			return 0;
		}	

		do
		{
			if ((pattern[0].type == UNUSED) || (pattern[1].type == QUESTIONMARK))
			{
				return matchquestion(pattern[0], &pattern[2], text, matchlength, nloops);
			}
			else if (pattern[1].type == STAR)
			{
				return matchstar(pattern[0], &pattern[2], text, matchlength, nloops);
			}
			else if (pattern[1].type == PLUS)
			{
				return matchplus(pattern[0], &pattern[2], text, matchlength, nloops);
			}
			else if ((pattern[0].type == END) && pattern[1].type == UNUSED)
			{
				return (text[0] == '\0');
			}
			/*  Branching is not working properly
			    else if (pattern[1].type == BRANCH)
			    {
			    return (matchpattern(pattern, text, nloops) || matchpattern(&pattern[2], text, nloops));
			    }
			 */
			(*matchlength)++;

			nloops = 0;

		}
		while ((text[0] != '\0') && pattern < endpattern && matchone(*pattern++, *text++));

		*matchlength = pre;
		return 0;
	}


};

using TinyRegex = TinyRegexInt<128>;

} // namespace gyeeta

