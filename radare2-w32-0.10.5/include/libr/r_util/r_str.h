#ifndef R_STR_H
#define R_STR_H

typedef int (*RStrRangeCallback) (void *, int);

/* TODO ..use as uppercase maybe? they are macros! */
#define strnull(x) (!x||!*x)
#define iswhitechar(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r')
#define iswhitespace(x) ((x)==' '||(x)=='\t')
#define isseparator(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r'||(x)==' '|| \
		(x)==','||(x)==';'||(x)==':'||(x)=='['||(x)==']'|| \
		(x)=='('||(x)==')'||(x)=='{'||(x)=='}')
#define ishexchar(x) ((x>='0'&&x<='9') ||  (x>='a'&&x<='f') ||  (x>='A'&&x<='F'))

static inline void r_str_rmch(char *s, char ch) {
	for (;*s; s++) {
		if (*s==ch)
			memmove (s, s+1, strlen (s));
	}
}
#define r_str_array(x,y) ((y>=0 && y<(sizeof(x)/sizeof(*x)))?x[y]:"")
R_API const char *r_str_pad(const char ch, int len);
R_API const char *r_str_rchr(const char *base, const char *p, int ch);
R_API const char *r_str_closer_chr(const char *b, const char *s);
R_API int r_str_bounds(const char *str, int *h);
R_API char *r_str_crop(const char *str, unsigned int x, unsigned int y, unsigned int x2, unsigned int y2);
R_API int r_str_len_utf8(const char *s);
R_API int r_str_len_utf8char(const char *s, int left);
R_API void r_str_filter_zeroline(char *str, int len);
R_API int r_str_write(int fd, const char *b);
R_API void r_str_ncpy(char *dst, const char *src, int n);
R_API void r_str_sanitize(char *c);
R_API const char *r_str_casestr(const char *a, const char *b);
R_API const char *r_str_lastbut(const char *s, char ch, const char *but);
R_API int r_str_split(char *str, char ch);
R_API char* r_str_replace(char *str, const char *key, const char *val, int g);
R_API char *r_str_replace_in(char *str, ut32 sz, const char *key, const char *val, int g);
#define r_str_cpy(x,y) memmove(x,y,strlen(y)+1);
R_API int r_str_bits(char *strout, const ut8 *buf, int len, const char *bitz);
R_API int r_str_bits64(char *strout, ut64 in);
R_API ut64 r_str_bits_from_string(const char *buf, const char *bitz);
R_API int r_str_rwx(const char *str);
R_API int r_str_replace_char(char *s, int a, int b);
R_API int r_str_replace_char_once(char *s, int a, int b);
R_API const char *r_str_rwx_i(int rwx);
R_API void r_str_writef(int fd, const char *fmt, ...);
R_API char *r_str_arg_escape(const char *arg);
R_API char **r_str_argv(const char *str, int *_argc);
R_API void r_str_argv_free(char **argv);
R_API char *r_str_new(const char *str);
R_API int r_str_is_printable(const char *str);
R_API char *r_str_concatlen(char *ptr, const char *string, int slen);
R_API char *r_str_newf(const char *fmt, ...);
R_API char *r_str_newlen(const char *str, int len);
R_API const char *r_str_bool(int b);
R_API const char *r_str_ansi_chrn(const char *str, int n);
R_API int r_str_ansi_len(const char *str);
R_API int r_str_ansi_chop(char *str, int str_len, int n);
R_API int r_str_ansi_filter(char *str, char **out, int **cposs, int len);
R_API char *r_str_ansi_crop(const char *str, unsigned int x, unsigned int y, unsigned int x2, unsigned int y2);
R_API int r_str_word_count(const char *string);
R_API int r_str_char_count(const char *string, char ch);
R_API char *r_str_word_get0set(char *stra, int stralen, int idx, const char *newstr, int *newlen);
R_API int r_str_word_set0(char *str);
R_API const char *r_str_word_get0(const char *str, int idx);
R_API char *r_str_word_get_first(const char *string);
R_API char *r_str_chop(char *str);
R_API const char *r_str_chop_ro(const char *str);
R_API char *r_str_trim_head(char *str);
R_API const char *r_str_trim_const(const char *str);
R_API char *r_str_trim_tail(char *str);
R_API char *r_str_trim_head_tail(char *str);
R_API ut32 r_str_hash(const char *str);
R_API ut64 r_str_hash64(const char *str);
R_API char *r_str_clean(char *str);
R_API int r_str_nstr(char *from, char *to, int size);
R_API const char *r_str_lchr(const char *str, char chr);
R_API const char *r_sub_str_lchr(const char *str, int start, int end, char chr);
R_API const char *r_sub_str_rchr(const char *str, int start, int end, char chr);
R_API char *r_str_ichr(char *str, char chr);
R_API int r_str_ccmp(const char *dst, const char *orig, int ch);
R_API int r_str_cmp(const char *dst, const char *orig, int len);
R_API int r_str_ccpy(char *dst, char *orig, int ch);
R_API const char *r_str_get(const char *str);
R_API char *r_str_ndup(const char *ptr, int len);
R_API char *r_str_dup(char *ptr, const char *string);
R_API void *r_str_free(void *ptr);
R_API int r_str_inject(char *begin, char *end, char *str, int maxlen);
R_API int r_str_delta(char *p, char a, char b);
R_API void r_str_filter(char *str, int len);
R_API const char * r_str_tok(const char *str1, const char b, size_t len);

typedef void(*str_operation)(char *c);

R_API int r_str_do_until_token(str_operation op, char *str, const char tok);

R_API void r_str_const_free();
R_API const char *r_str_const(const char *ptr);

R_API int r_str_re_match(const char *str, const char *reg);
R_API int r_str_re_replace(const char *str, const char *reg, const char *sub);
R_API int r_str_unescape(char *buf);
R_API char *r_str_escape(const char *buf);
R_API char *r_str_escape_dot(const char *buf);
R_API void r_str_uri_decode(char *buf);
R_API char *r_str_uri_encode(const char *buf);
R_API char *r_str_utf16_decode(const ut8 *s, int len);
R_API int r_str_utf16_to_utf8(ut8 *dst, int len_dst, const ut8 *src, int len_src, int little_endian);
R_API char *r_str_utf16_encode(const char *s, int len);
R_API char *r_str_home(const char *str);
R_API int r_str_nlen(const char *s, int n);
R_API int r_wstr_clen(const char *s);
R_API char *r_str_prefix(char *ptr, const char *string);
R_API char *r_str_prefix_all(char *s, const char *pfx);
R_API char *r_str_concat(char *ptr, const char *string);
R_API char *r_str_concatf(char *ptr, const char *fmt, ...);
R_API char *r_str_concatch(char *x, char y);
R_API void r_str_case(char *str, bool up);
R_API void r_str_chop_path(char *s);
R_API ut8 r_str_contains_macro(const char *input_value);
R_API void r_str_truncate_cmd(char *string);
R_API char* r_str_replace_thunked(char *str, char *clean, int *thunk, int clen,
				  const char *key, const char *val, int g);
R_API char *r_hex_from_c(const char *code);
R_API bool r_str_glob(const char *str, const char *glob);
R_API int r_str_binstr2bin(const char *str, ut8 *out, int outlen);
R_API char *r_str_between(const char *str, const char *prefix, const char *suffix);

#endif //  R_STR_H
