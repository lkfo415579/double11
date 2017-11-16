# -*- coding: utf-8 -*-
#!/usr/bin/env python
import sys
from regex import Regex, UNICODE
import codecs

#reload(sys)
#sys.setdefaultencoding('utf-8')


class Generizer(object):
    def __init__(self):
        self.__author__ = "Revo"
        self.__date__ = "2017-10-24"
        # email address: 
        self.__email_addr = Regex(r'([\w\.-]+@[\w\.-]+)')
        # url address:
        self.__url_addr = Regex(r'(?P<url>https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)|[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*))')
        #self.__date_list = ["a.m","p.m","A.M","P.M"]
        # Numbers
        self.__numbers = Regex(r'([+\-]?\d*[\.,]?\d+[\d\.,+\-eE]*)')
        # Replace with add one
        self.__addone = Regex(r'(__(NUM|EMAIL|URL)__)')
        # double space to single
        self.__spaces = Regex(r'\s+', flags=UNICODE)
        #
        self.__counter = dict()
    def _add1_NUM(self,match):
        self.__counter += 1
        return " __NUM"+str(self.__counter)+"__ "
    def _add1_EMAIL(self,match):
        self.__counter += 1
        return " __EMAIL"+str(self.__counter)+"__ "
    def _add1_URL(self,match):
        self.__counter += 1
        return " __URL"+str(self.__counter)+"__ "
    def _filter_AM_NUM(self,match):
        #if match.group("url") in self.__date_list or match.group("url").replace(".","").isdigit():
        #    return match.group("url")
        return " __URL__ "
    def _add1(self,match):
        type = match.group(0)[2:-2]
        try:
            self.__counter[type] += 1
        except:
            self.__counter[type] = 1
        return "__" + type +str(self.__counter[type]) + "__"
    def tokenize(self, text):
        #normalize
        text = text.replace(" @ ","@")
        text = text.replace(" . ",".")
        text = text.replace("http : // ","http://")
        #
        text = self.__email_addr.sub(" __EMAIL__ ", text)
        #" __URL__ "
        text = self.__url_addr.sub(" __URL__ ", text)
        #text = self.__numbers.sub(" __NUM__ ", text)
        text = self.__addone.sub(self._add1,text)
        self.__counter = {}
        # spaces to single space
        text = self.__spaces.sub(' ', text)
        #
        return text

if __name__ == '__main__':
    sys.stdin = codecs.getreader('utf-8')(sys.stdin)
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout)
    Real_Generizer = Generizer()
    for line in sys.stdin:
        #print line.strip()
        #print Real_Generizer.tokenize(line)
        sys.stdout.write(Real_Generizer.tokenize(line).strip()+"\n")
        