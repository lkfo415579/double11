#!/usr/bin/env python
# coding=utf-8

"""
A simple de-tokenizer for MT post-processing.

Library usage:

Command-line usage:

    ./detokenize.py [-c] [-l LANG] [-e ENCODING] [input-file output-file]
    
    -e = use the given encoding (default: UTF-8)
    -l = use rules for the given language (ISO-639-2 code, default: en)
    -c = capitalize the first words of sentences
      
    If no input and output files are given, the de-tokenizer will read
    STDIN and write to STDOUT.
"""

from __future__ import unicode_literals
from regex import Regex, UNICODE, IGNORECASE
#from fileprocess import process_lines
import sys
import logging
import getopt


__author__ = "Liang Tian,REVO"
__date__ = "2017/10/26"

DEFAULT_ENCODING = 'UTF-8'


class Detokenizer(object):
    """\
    A simple de-tokenizer class.
    """

    # Moses special characters de-escaping
    ESCAPES = [('&bar;', '|'),
               ('&lt; ', '<'),
               (' &gt;', '>'),
               ('&lt;', '<'),
               ('&gt;', '>'),
               ('&bra;', '['),
               ('&ket;', ']'),
               ('&amp;', '&'),
			   ('&quot;','"')]  # should go last to prevent double de-escaping

    #Nmt special characters de-escaping, liangss add 2017/01/19
    NMT_ESCAPES = [('& bar;', '|'),
               ('& lt;', '<'),
               ('& lt ;', '<'),
               ('& gt;', '>'),
               ('& gt ;', '>'),
               ('& bra;', '['),
               #('& bra ;', '['),
               ('&bra ;', '['),
               ('& ket;', ']'),
               #('& ket ;', ']'),
               ('&ket ;', ']'),
               ('& amp;','&'),
               ('& #183;','· ')
              ]
    KO_PARTICLE=['가','이','께서','를','을','의','에','에게','께','한테','더러',
                 '에서','에게서','한테서','께서','로','으로','으로','로써','으로써',
                 '로서','으로서','보다','처럼','만큼', '만치','과','와','하고','라고','고',
                 '아','야','여','이여','이시여','는','은','ㄹ랑','을랑','란','이란','도','조차','마저',
                 '부터','까지','만','밖에','마다','치고','야','이야','라야','이라야','야말로',
                 '이야말로','나마','이나마','라도','이라도','나','이나','든지','이든지','커녕',
                 '다가','마는','그려','요','있']

    # Contractions for different languages
    CONTRACTIONS = {'en': r'^\p{Alpha}+(\'(ll|ve|re|[dsm])|n\'t)$',
                    'fr': r'^([cjtmnsdl]|qu)\'\p{Alpha}+$',
                    'es': r'^[dl]\'\p{Alpha}+$',
                    'it': r'^\p{Alpha}*(l\'\p{Alpha}+|[cv]\'è)$',
                    'cs': r'^\p{Alpha}+[-–](mail|li)$', }

    KO_FINAL_PUNCT = [(' ,', ','),
                   (' .', '.'),
                   (' !', '!'),
                   (' ?', '?'),
                   (' ;', ';'),
                   (' !', '!'),
                   ('[ ', '['),
                   (' ]', ']')]

    
    AFTER_ESCAPES_NOSPACE_CHAR = [(' [', '['),
 				  ('[ ','['),
                                  (' ]', ']'),
                                  ('] ', ']')]
    def __init__(self, options={}):
        """\
        Constructor (pre-compile all needed regexes).
        """
        # process options
        self.moses_deescape = True if options.get('moses_deescape') else False
        self.language = options['language']
        #print "WTF,",self.language
        self.capitalize_sents = True if options.get('capitalize_sents') else False
        # compile regexes
        #shuffix_space
        self.__currency_or_init_punct = Regex(r'^[\p{Sc}\(\[\{\¿\¡]+$')
        #prefix_space
        self.__noprespace_punct = Regex(r'^[\/\<\>\,\，\、\。\：\；\.\?\!\:\;\\\%\}\]\)\‰]+$')
        self.__cjk_chars = Regex(r'[\u1100-\u11FF\u2E80-\uA4CF\uA840-\uA87F'
                                 + r'\uAC00-\uD7AF\uF900-\uFAFF\uFE30-\uFE4F'
                                 + r'\uFF65-\uFFDC]')
        self.__final_punct = Regex(r'([\.!?])([\'\"\)\]\p{Pf}\%])*$')

        # language-specific regexes
        self.__fr_prespace_punct = Regex(r'^[\?\!\:\;\\\%]$')
        self.__contract = None


	#liangss add chinese numberic unit  nospace process
        self.__nospace_chinese_numberic_unit = Regex(r'\d+[mMgGbB\%]*')
        self.special_chinese_symbol = Regex(r'[\，\%\‰]')

	#liangss add English date comma process
        self.__add_english_date_comma = Regex(r'\d+\s+[January|February|March|April|May|June|July|August|September|October|November|December]+')
	#liangss chinese character detokenize
        #self.__noprespace_punct_chinese = Regex(r'^[\，\。\？\！\\\%\\]\)]+$')
        if self.language in self.CONTRACTIONS:
            self.__contract = Regex(self.CONTRACTIONS[self.language],
                                    IGNORECASE)

    def detokenize(self, text):
        """\
        Detokenize the given text using current settings.
        """
        reload(sys)
        sys.setdefaultencoding('utf8') 
        
        #can not trim space between each words
        if self.language == 'ko' or self.language == 'nko':

            #parse space before end-punct
            for char, repl in self.KO_FINAL_PUNCT:
                text = text.replace(char, repl)

            #parse space before KO_PARTICLE
            for char in self.KO_PARTICLE:
                text = text.replace(' ' + char, char)
        else: 
            # split text
            words = text.split(' ')
            #print "Detoken : ",
            #print words
            # paste text back, omitting spaces where needed 
            text = ''
            pre_spc = ' '
            quote_count = {'\'': 0, '"': 0, '`': 0}
            for pos, word in enumerate(words):
                
                # remove spaces in between CJK chars
                if self.__cjk_chars.match(text[-1:]) and \
                        self.__cjk_chars.match(word[:1]):
                    text += word
                    pre_spc = ' '
                    #print "CJK:%d,%s" % (pos,word)
                # no space after currency and initial punctuation
                elif self.__currency_or_init_punct.match(word):
                    text += pre_spc + word
                    pre_spc = ''
                # no space before commas etc. (exclude some punctuation for French)
                elif self.__noprespace_punct.match(word) and \
                        ((self.language != 'fr' and self.language != 'nfr') or not
                         self.__fr_prespace_punct.match(word)):
                    text += word
                    #pre_spc = ' '
                    pre_spc = ' '
                    #print "SELF,",self.language
                    if self.language == 'zh' or self.language == 'nzh':
                        pre_spc = ''
                        #print "HERE"
                    #print "__noprespace_punct:%d,[%s]" % (pos,word)
                # contractions with comma or hyphen 
                elif word in "'--" and pos > 0 and pos < len(words) - 1 \
                        and self.__contract is not None \
                        and self.__contract.match(''.join(words[pos - 1:pos + 2])):
                    text += word
                    pre_spc = ''
                    #print word
                # handle quoting
                elif word in '\'"„“”‚‘’`':
                    # detect opening and closing quotes by counting 
                    # the appropriate quote types
                    quote_type = word
                    if quote_type in '„“”':
                        quote_type = '"'
                    elif quote_type in '‚‘’':
                        quote_type = '\''
                    # exceptions for true Unicode quotes in Czech & German
                    if self.language in ['cs', 'de'] and word in '„‚':
                        quote_count[quote_type] = 0
                    elif self.language in ['cs', 'de'] and word in '“‘':
                        quote_count[quote_type] = 1
                    # special case: possessives in English ("Jones'" etc.)                    
                    if self.language == 'en' and text.endswith('s'):
                        text += word
                        pre_spc = ' '
                    # really a quotation mark
                    else:
                        # opening quote
                        if quote_count[quote_type] % 2 == 0:
                            text += pre_spc + word
                            pre_spc = ''
                        # closing quote
                        else:
                            text += word
                            pre_spc = ' '
                        quote_count[quote_type] += 1

                # chinese numberic unit no space process
                elif (self.__nospace_chinese_numberic_unit.match(word) or self.special_chinese_symbol.match(word)) and (self.language == 'zh' or self.language=='nzh'):
                    #print word
                    text += word
                    pre_spc = ''
                # keep spaces around normal words
                elif (word in "-"):
                    #all \s-\s will be no space
                    text += word
                    pre_spc = ''
                else:
                    #print "normal:%d,%s" % (pos,word)
                    text += pre_spc + word
                    pre_spc = ' '
            # de-escape chars that are special to Moses
            if self.moses_deescape:
                for char, repl in self.ESCAPES:
                    text = text.replace(char, repl)

	        #de-escape chars that are special to NMTServer 
                for char, repl in self.NMT_ESCAPES:
                    text = text.replace(char, repl)

	for char, repl in self.AFTER_ESCAPES_NOSPACE_CHAR:
            text = text.replace(char, repl)

        # add comma to english date 
        if self.language == 'en' or self.language=='nen':
            date_pattern = self.__add_english_date_comma.search(text)
            if date_pattern is not None:
                text = text.replace(date_pattern.group(),date_pattern.group()+',')
           
        # strip leading/trailing space
        text = text.strip()
        # capitalize, if the sentence ends with a final punctuation
        if self.capitalize_sents and self.__final_punct.search(text):
            text = text[0].upper() + text[1:]
        return text


def display_usage():
    """\
    Display program usage information.
    """
    print >> sys.stderr, __doc__


if __name__ == '__main__':
    # parse options
    opts, filenames = getopt.getopt(sys.argv[1:], 'e:hcl:')
    options = {}
    help = False
    encoding = DEFAULT_ENCODING
    for opt, arg in opts:
        if opt == '-e':
            encoding = arg
        elif opt == '-l':
            options['language'] = arg
        elif opt == '-c':
            options['capitalize_sents'] = True
        elif opt == '-h':
            help = True
    # display help
    if len(filenames) > 2 or help:
        display_usage()
        sys.exit(1)
    # process the input
    detok = Detokenizer(options)
    #process_lines(detok.detokenize, filenames, encoding)
