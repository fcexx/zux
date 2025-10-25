#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

static void buf_putc(char** p, char* end, int c, int* count){
	if (*p < end) **p = (char)c;
	(*p)++;
	if (count) (*count)++;
}

static void out_number(char** p, char* end, unsigned long long v, int base, int width, int zpad, int upper, int* count){
	char tmp[64]; int i=0;
	const char* digs = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	if (v==0) tmp[i++]='0';
	else { while (v){ tmp[i++] = digs[v % (unsigned)base]; v /= (unsigned)base; } }
	int pad = width - i;
	while (pad-- > 0) buf_putc(p, end, zpad?'0':' ', count);
	while (i>0) buf_putc(p, end, tmp[--i], count);
}

int vsnprintf(char* buf, size_t size, const char* fmt, va_list ap){
	if (!buf || !fmt) return 0;
	char* out = buf;
	char* end = size ? (buf + (size - 1)) : buf; // reserve for NUL
	int count = 0;
	for (const char* f = fmt; *f; ++f){
		if (*f != '%'){ buf_putc(&out, end, *f, &count); continue; }
		// parse flags and width
		int zpad=0; int width=0; int long_count=0; int is_signed=0; int upper=0; 
		++f;
		if (*f=='0'){ zpad=1; ++f; }
		while (*f>='0'&&*f<='9'){ width = width*10 + (*f - '0'); ++f; }
		while (*f=='l'){ long_count++; ++f; }
		char spec = *f ? *f : 0;
		switch(spec){
			case 'd': case 'i': {
				is_signed = 1;
				long long v = (long_count>=2)? va_arg(ap,long long) : (long_count==1)? (long long)va_arg(ap,long) : (long long)va_arg(ap,int);
				if (v<0){ buf_putc(&out,end,'-',&count); v = -v; if (width>0) width--; }
				out_number(&out, end, (unsigned long long)v, 10, width, zpad, 0, &count); break; }
			case 'u': {
				unsigned long long v = (long_count>=2)? va_arg(ap,unsigned long long) : (long_count==1)? (unsigned long long)va_arg(ap,unsigned long) : (unsigned long long)va_arg(ap,unsigned int);
				out_number(&out, end, v, 10, width, zpad, 0, &count); break; }
			case 'x': case 'X': {
				upper = (spec=='X');
				unsigned long long v = (long_count>=2)? va_arg(ap,unsigned long long) : (long_count==1)? (unsigned long long)va_arg(ap,unsigned long) : (unsigned long long)va_arg(ap,unsigned int);
				out_number(&out, end, v, 16, width, zpad, upper, &count); break; }
			case 'p': {
				unsigned long long v = (unsigned long long)va_arg(ap, void*);
				buf_putc(&out,end,'0',&count); buf_putc(&out,end,'x',&count);
				out_number(&out, end, v, 16, (width>2)?(width-2):0, zpad, 0, &count); break; }
			case 'c': { int c = va_arg(ap,int); buf_putc(&out,end,c,&count); break; }
			case 's': { const char* s = va_arg(ap,const char*); if(!s) s="(null)"; while (*s) buf_putc(&out,end,*s++,&count); break; }
			case '%': { buf_putc(&out,end,'%',&count); break; }
			default: { buf_putc(&out,end,'%',&count); if(spec) buf_putc(&out,end,spec,&count); break; }
		}
	}
	if (size) *out = '\0';
	return count;
}

int snprintf(char* buf, size_t size, const char* fmt, ...){
	va_list ap; va_start(ap, fmt); int r = vsnprintf(buf, size, fmt, ap); va_end(ap); return r;
}

int vsprintf(char* buf, const char* fmt, va_list ap){
	return vsnprintf(buf, (size_t)-1, fmt, ap);
}

int sprintf(char* buf, const char* fmt, ...){
	va_list ap; va_start(ap, fmt); int r = vsnprintf(buf, (size_t)-1, fmt, ap); va_end(ap); return r;
}
