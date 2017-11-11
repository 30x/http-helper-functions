Some helper functions for working with the Node http module

I wrote these because:

1. Writing code that uses the Node built-in http module directly is a bit tedious
2. I was repulsed by the size and complexity of popular modules like [request] (https://github.com/request/request)

This module is not trying to compete with [request] (https://github.com/request/request) - it only provides a few very simple functions to help reduce boilerplate when using the http module.
Some of the functions are a bit specific to the Apigee permissions service—the module should probably be split.

__

#	@(#)README	8.1 (Berkeley) 6/5/93
# $FreeBSD$

The file 65536words was extracted from the web2 file of FreeBSD with the following license

WEB ---- (introduction provided by jaw@riacs) -------------------------

Welcome to web2 (Webster's Second International) all 234,936 words worth.
The 1934 copyright has lapsed, according to the supplier.  The
supplemental 'web2a' list contains hyphenated terms as well as assorted
noun and adverbial phrases.  The wordlist makes a dandy 'grep' victim.

     -- James A. Woods    {ihnp4,hplabs}!ames!jaw    (or jaw@riacs)

Country names are stored in the file /usr/share/misc/iso3166.


FreeBSD Maintenance Notes ---------------------------------------------

Note that FreeBSD is not maintaining a historical document, we're
maintaining a list of current [American] English spellings.

A few words have been removed because their spellings have depreciated.
This list of words includes:
    corelation (and its derivatives)	"correlation" is the preferred spelling
    freen				typographical error in original file
    freend				archaic spelling no longer in use;
					masks common typo in modern text

--

A list of technical terms has been added in the file 'freebsd'.  This
word list contains FreeBSD/Unix lexicon that is used by the system
documentation.  It makes a great ispell(1) personal dictionary to
supplement the standard English language dictionary.