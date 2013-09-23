/*
* ** dnsmap - DNS Network Mapper by pagvac
* ** Copyright (C) 2010 gnucitizen.org
* **
* ** This program is free software; you can redistribute it and/or modify
* ** it under the terms of the GNU General Public License as published by
* ** the Free Software Foundation; either version 2 of the License, or
* ** (at your option) any later version.
* **
* ** This program is distributed in the hope that it will be useful,
* ** but WITHOUT ANY WARRANTY; without even the implied warranty of
* ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* ** GNU General Public License for more details.
* **
* ** You should have received a copy of the GNU General Public License
* ** along with this program; if not, write to the Free Software
* ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
* */

#define MAXSUBSIZE 	100
#define MAXSTRSIZE 	200
#define BANNER 		"dnsmap 0.30 - DNS Network Mapper by pagvac (gnucitizen.org)\n\n"
#define USAGE 		"usage: dnsmap [options] <target-domain>\noptions:\n"\
			"-w <wordlist-file>\n-r <regular-results-file>\n-c <csv-results-file>\n"\
			"-d <delay-millisecs>\n-i <ips-to-ignore> (useful if you're obtaining false positives)\n\n"
#define EXAMPLES 	"e.g.:\ndnsmap target-domain.foo\n"\
			"dnsmap target-domain.foo -w yourwordlist.txt -r /tmp/domainbf_results.txt\n"\
			"dnsmap target-fomain.foo -r /tmp/ -d 3000\n"\
			"dnsmap target-fomain.foo -r ./domainbf_results.txt\n\n"
#define INTIPWARN	"[+] warning: internal IP address disclosed\n"
#define SAMESITEXSSWARN "[+] warning: domain might be vulnerable to \"same site\" scripting (http://snipurl.com/etbcv)\n"
#define INPUTERR	"[+] error: entered parameter(s) is/are too long!\n"
#define DELAYINPUTERR	"[+] error: delay must be between 1 and 300000 milliseconds (5 minutes)!\n"
#define FILTIPINPUTERR	"[+] error: the maxium number of IPs to filter is 5!\n"
#define DOMAINERR	"[+] error: entered domain is not valid!\n"
#define OPENDNSMSG	"[+] openDNS detected. good! this might help with performance\n"

#define WILDCARDWARN	"[+] warning: domain might use wildcards. "\
			"%s will be ignored from results\n", wildcardIpStr
#define BUILTINMSG	"%s%s%s\n", "[+] searching (sub)domains for ", argv[1], " using built-in wordlist"

#define FALSE 0
#define TRUE 1

#define DEBUG 1

#if DEBUG > 0

#define DEBUG_MSG(fmt, arg...) \
do {\
    fprintf(stderr, "%s:"fmt,\
    __FUNCTION__, \
    ##arg); \
} while (0)

#else

#define DEBUG_MSG(fmt, arg...)

#endif


// buil-in list of subdomains
// mainly targeting English and Spanish keywords
char sub[][MAXSUBSIZE]=
{
"a",
"aa",
"ab",
"ac",
"access",
"accounting",
"accounts",
"ad",
"admin",
"administrator",
"ae",
"af",
"ag",
"ah",
"ai",
"aix",
"aj",
"ak",
"al",
"am",
"an",
"ao",
"ap",
"apollo",
"aq",
"ar",
"archivos",
"as",
"at",
"au",
"aula",
"aulas",
"av",
"aw",
"ax",
"ay",
"ayuda",
"az",
"b",
"ba",
"backup",
"backups",
"bart",
"bb",
"bc",
"bd",
"be",
"beta",
"bf",
"bg",
"bh",
"bi",
"biblioteca",
"billing",
"bj",
"bk",
"bl",
"blackboard",
"blog",
"blogs",
"bm",
"bn",
"bo",
"bp",
"bq",
"br",
"bs",
"bsd",
"bt",
"bu",
"bv",
"bw",
"bx",
"by",
"bz",
"c",
"ca",
"carro",
"cart",
"cas",
"catalog",
"catalogo",
"catalogue",
"cb",
"cc",
"cd",
"ce",
"cf",
"cg",
"ch",
"chat",
"chimera",
"chronos", // time server?
"ci",
"citrix",
"cj",
"ck",
"cl",
"classroom",
"clientes",
"clients",
"cm",
"cn",
"co",
"connect",
"controller",
"correoweb",
"cp",
"cpanel",
"cq",
"cr",
"cs",
"csg",
"ct",
"cu",
"customers",
"cv",
"cw",
"cx",
"cy",
"cz",
"d",
"da",
"data",
"db",
"dbs",
"dc", // domain controller?
"dd",
"de",
"demo",
"demon",
"demostration",
"descargas",
"developers",
"development",
"df",
"dg",
"dh",
"di",
"diana",
"directory",
"dj",
"dk",
"dl",
"dm",
"dmz",
"dn",
"do",
"domain",
"domaincontroller",
"domain-controller",
"download",
"downloads",
"dp",
"dq",
"dr",
"ds",
"dt",
"du",
"dv",
"dw",
"dx",
"dy",
"dz",
"e",
"ea",
"eaccess",
"eb",
"ec",
"ed",
"ee",
"ef",
"eg",
"eh",
"ei",
"ej",
"ejemplo",
"ejemplos",
"ek",
"el",
"em",
"email",
"en",
"enrutador",
"eo",
"ep",
"eq",
"er",
"es",
"et",
"eu",
"ev",
"eventos",
"events",
"ew",
"ex",
"example",
"examples",
"exchange",
"extranet",
"ey",
"ez",
"f",
"fa",
"fb",
"fc",
"fd",
"fe",
"ff",
"fg",
"fh",
"fi",
"files",
"finance",
"firewall",
"fj",
"fk",
"fl",
"fm",
"fn",
"fo",
"foro",
"foros",
"forum",
"forums",
"fp",
"fq",
"fr",
"freebsd",
"fs",
"ft",
"ftp",
"ftpd",
"fu",
"fv",
"fw",
"fx",
"fy",
"fz",
"g",
"ga",
"galeria",
"gallery",
"gateway",
"gb",
"gc",
"gd",
"ge",
"gf",
"gg",
"gh",
"gi",
"gilford",
"gj",
"gk",
"gl",
"gm",
"gn",
"go",
"gp",
"gq",
"gr",
"groups",
"groupwise",
"gs",
"gt",
"gu",
"guest",
"guia",
"guide",
"gv",
"gw",
"gx",
"gy",
"gz",
"h",
"ha",
"hb",
"hc",
"hd",
"he",
"help",
"helpdesk",
"hera",
"heracles",
"hercules",
"hf",
"hg",
"hh",
"hi",
"hj",
"hk",
"hl",
"hm",
"hn",
"ho",
"home",
"homer",
"hotspot",
"hp",
"hq",
"hr",
"hs",
"ht",
"hu",
"hv",
"hw",
"hx",
"hy",
"hypernova",
"hz",
"i",
"ia",
"ib",
"ic",
"id",
"ie",
"if",
"ig",
"ih",
"ii",
"ij",
"ik",
"il",
"im",
"images",
"imail",
"imap",
"imap3",
"imap3d",
"imapd",
"imaps",
"imgs",
"imogen",
"in",
"inmuebles",
"internal",
"interno",
"intranet",
"io",
"ip",
"ip6",
"ipsec",
"ipv6",
"iq",
"ir",
"irc",
"ircd",
"is",
"isa", //ISA proxy?
"it",
"iu",
"iv",
"iw",
"ix",
"iy",
"iz",
"j",
"ja",
"jabber",
"jb",
"jc",
"jd",
"je",
"jf",
"jg",
"jh",
"ji",
"jj",
"jk",
"jl",
"jm",
"jn",
"jo",
"jp",
"jq",
"jr",
"js",
"jt",
"ju",
"jupiter",
"jv",
"jw",
"jx",
"jy",
"jz",
"k",
"ka",
"kb",
"kc",
"kd",
"ke",
"kf",
"kg",
"kh",
"ki",
"kj",
"kk",
"kl",
"km",
"kn",
"ko",
"kp",
"kq",
"kr",
"ks",
"kt",
"ku",
"kv",
"kw",
"kx",
"ky",
"kz",
"l",
"la",
"lab",
"laboratories",
"laboratorio",
"laboratory",
"labs",
"lb",
"lc",
"ld",
"le",
"lf",
"lg",
"lh",
"li",
"library",
"linux",
"lisa",
"lj",
"lk",
"ll",
"lm",
"ln",
"lo",
"localhost",
"log",
"login",
"logon",
"logs",
"lp",
"lq",
"lr",
"ls",
"lt",
"lu",
"lv",
"lw",
"lx",
"ly",
"lz",
"m",
"ma",
"mail",
"mailgate",
"manager",
"marketing",
"mb",
"mc",
"md",
"me",
"media",
"member",
"members",
"mercury", // MX server?
"meta",
"meta01",
"meta02",
"meta03",
"meta1",
"meta2",
"meta3",
"mf",
"mg",
"mh",
"mi",
"miembros",
"minerva",
"mj",
"mk",
"ml",
"mm",
"mn",
"mo",
"mob",
"mobile",
"moodle",
"movil",
"mp",
"mq",
"mr",
"ms",
"mssql",
"mt",
"mu",
"mv",
"mw",
"mx",
"mx0",
"mx01",
"mx02",
"mx03",
"mx1",
"mx2",
"mx3",
"my",
"mysql",
"mz",
"n",
"na",
"nb",
"nc",
"nd",
"ne",
"nelson",
"neon",
"net",
"netmail",
"news",
"nf",
"ng",
"nh",
"ni",
"nj",
"nk",
"nl",
"nm",
"nn",
"no",
"novell",
"np",
"nq",
"nr",
"ns",
"ns0",
"ns01",
"ns02",
"ns03",
"ns1",
"ns2",
"ns3",
"nt",
"ntp",
"nu",
"nv",
"nw",
"nx",
"ny",
"nz",
"o",
"oa",
"ob",
"oc",
"od",
"oe",
"of",
"og",
"oh",
"oi",
"oj",
"ok",
"ol",
"om",
"on",
"online",
"oo",
"op",
"oq",
"or",
"ora",
"oracle",
"os",
"osx",
"ot",
"ou",
"ov",
"ow",
"owa",
"ox",
"oy",
"oz",
"p",
"pa",
"partners",
"pb",
"pc",
"pcanywhere",
"pd",
"pe",
"pegasus",
"pendrell",
"personal",
"pf",
"pg",
"ph",
"photo",
"photos",
"pi",
"pj",
"pk",
"pl",
"pm",
"pn",
"po",
"pop",
"pop3",
"portal",
"postgresql",
"postman",
"postmaster",
"pp", // preprod?
"ppp",
"pq",
"pr",
"preprod",
"pre-prod",
"private",
"prod",
"proxy",
"prueba",
"pruebas",
"ps",
"pt",
"pu",
"pub",
"public",
"pv",
"pw",
"px",
"py",
"pz",
"q",
"qa",
"qb",
"qc",
"qd",
"qe",
"qf",
"qg",
"qh",
"qi",
"qj",
"qk",
"ql",
"qm",
"qn",
"qo",
"qp",
"qq",
"qr",
"qs",
"qt",
"qu",
"qv",
"qw",
"qx",
"qy",
"qz",
"r",
"ra",
"ras",
"rb",
"rc",
"rd",
"re",
"remote",
"reports",
"research",
"restricted",
"rf",
"rg",
"rh",
"ri",
"rj",
"rk",
"rl",
"rm",
"rn",
"ro",
"robinhood",
"router",
"rp",
"rq",
"rr",
"rs",
"rt",
"rtr",
"ru",
"rv",
"rw",
"rx",
"ry",
"rz",
"s",
"sa",
"sales",
"sample",
"samples",
"sandbox",
"sb",
"sc",
"sd",
"se",
"search",
"secure",
"seguro",
"server",
"services",
"servicios",
"servidor",
"sf",
"sg",
"sh",
"sharepoint",
"shop",
"shopping",
"si",
"sj",
"sk",
"sl",
"sm",
"sms",
"smtp",
"sn",
"so",
"socios",
"solaris",
"soporte",
"sp", // sharepoint?
"sq",
"sql",
"squirrel",
"squirrelmail",
"sr",
"ss",
"ssh",
"st",
"staff",
"staging",
"stats",
"su",
"sun",
"support",
"sv",
"sw",
"sx",
"sy",
"sz",
"t",
"ta",
"tb",
"tc",
"td",
"te",
"test",
"tf",
"tftp",
"tg",
"th",
"ti",
"tienda",
"tj",
"tk",
"tl",
"tm",
"tn",
"to",
"tp",
"tq",
"tr",
"ts",
"tt",
"tu",
"tunnel",
"tv",
"tw",
"tx",
"ty",
"tz",
"u",
"ua",
"uat",
"ub",
"uc",
"ud",
"ue",
"uf",
"ug",
"uh",
"ui",
"uj",
"uk",
"ul",
"um",
"un",
"unix",
"uo",
"up",
"upload",
"uploads",
"uq",
"ur",
"us",
"ut",
"uu",
"uv",
"uw",
"ux",
"uy",
"uz",
"v",
"va",
"vb",
"vc",
"vd",
"ve",
"ventas",
"vf",
"vg",
"vh",
"vi",
"virtual",
"vista",
"vj",
"vk",
"vl",
"vm",
"vn",
"vnc",
"vo",
"vp",
"vpn",
"vpn1",
"vpn2",
"vpn3",
"vq",
"vr",
"vs",
"vt",
"vu",
"vv",
"vw",
"vx",
"vy",
"vz",
"w",
"wa",
"wap",
"wb",
"wc",
"wd",
"we",
"web",
"web0",
"web01",
"web02",
"web03",
"web1",
"web2",
"web3",
"webadmin",
"webct",
"weblog",
"webmail",
"webmaster",
"webmin",
"wf",
"wg",
"wh",
"wi",
"win",
"windows",
"wj",
"wk",
"wl",
"wm",
"wn",
"wo",
"wp",
"wq",
"wr",
"ws",
"wt",
"wu",
"wv",
"ww",
"ww0",
"ww01",
"ww02",
"ww03",
"ww1",
"ww2",
"ww3",
"www",
"www0",
"www01",
"www02",
"www03",
"www1",
"www2",
"www3",
"wx",
"wy",
"wz",
"x",
"xa",
"xanthus",
"xb",
"xc",
"xd",
"xe",
"xf",
"xg",
"xh",
"xi",
"xj",
"xk",
"xl",
"xm",
"xn",
"xo",
"xp",
"xq",
"xr",
"xs",
"xt",
"xu",
"xv",
"xw",
"xx",
"xy",
"xz",
"y",
"ya",
"yb",
"yc",
"yd",
"ye",
"yf",
"yg",
"yh",
"yi",
"yj",
"yk",
"yl",
"ym",
"yn",
"yo",
"yp",
"yq",
"yr",
"ys",
"yt",
"yu",
"yv",
"yw",
"yx",
"yy",
"yz",
"z",
"za",
"zb",
"zc",
"zd",
"ze",
"zeus",
"zf",
"zg",
"zh",
"zi",
"zj",
"zk",
"zl",
"zm",
"zn",
"zo",
"zp",
"zq",
"zr",
"zs",
"zt",
"zu",
"zv",
"zw",
"zx",
"zy",
"zz"
};
